use libseccomp::ScmpFilterContext;
use std::{collections::HashMap, io, time::Duration};

use crossterm::event::{self, Event, KeyCode};
use ratatui::{prelude::*, widgets::*};
use thiserror::Error;

use crate::filters::{
    load_abstract_groups, AbstractGroupDef, GroupRule, ProfileError, SyscallRule,
};
use crate::monitor::{SeccompEvent, SeccompMonitor};

#[derive(Error, Debug)]
pub enum TuiError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("Profile error: {0}")]
    Profile(#[from] ProfileError),
}

type Result<T> = std::result::Result<T, TuiError>;

// ============================================================================
// TUI Modes
// ============================================================================

pub enum TuiMode {
    Explore,
    Monitor(SeccompMonitor),
}

// ============================================================================
// Tree Node Structure
// ============================================================================

#[derive(Clone, Debug)]
enum TreeNode {
    Group {
        name: String,
        children: Vec<TreeNode>,
        expanded: bool,
    },
    Syscall {
        rule: SyscallRule,
    },
}

impl TreeNode {
    fn name(&self) -> &str {
        match self {
            TreeNode::Group { name, .. } => name,
            TreeNode::Syscall { rule } => &rule.name,
        }
    }

    fn is_expanded(&self) -> bool {
        match self {
            TreeNode::Group { expanded, .. } => *expanded,
            TreeNode::Syscall { .. } => false,
        }
    }

    fn toggle_expand(&mut self) {
        if let TreeNode::Group { expanded, .. } = self {
            *expanded = !*expanded;
        }
    }
}

// ============================================================================
// Tree State
// ============================================================================

struct TreeState {
    nodes: Vec<TreeNode>,
    selected: usize,
    scroll_offset: usize,
}

impl TreeState {
    fn new(groups: HashMap<String, AbstractGroupDef>) -> Self {
        let mut nodes = Vec::new();

        // Sort groups by name for consistent display
        let mut sorted_names: Vec<_> = groups.keys().cloned().collect();
        sorted_names.sort();

        for name in sorted_names {
            if let Some(def) = groups.get(&name) {
                nodes.push(Self::build_tree_node(name, def.clone(), &groups));
            }
        }

        Self {
            nodes,
            selected: 0,
            scroll_offset: 0,
        }
    }

    fn build_tree_node(
        name: String,
        def: AbstractGroupDef,
        groups: &HashMap<String, AbstractGroupDef>,
    ) -> TreeNode {
        Self::build_tree_node_with_visited(name, def, groups, &mut std::collections::HashSet::new())
    }

    fn build_tree_node_with_visited(
        name: String,
        def: AbstractGroupDef,
        groups: &HashMap<String, AbstractGroupDef>,
        visited: &mut std::collections::HashSet<String>,
    ) -> TreeNode {
        // Prevent circular references
        if visited.contains(&name) {
            return TreeNode::Group {
                name: format!("{} (circular reference)", name),
                children: vec![],
                expanded: false,
            };
        }

        visited.insert(name.clone());
        let mut children = Vec::new();

        for rule in &def.rules {
            match rule {
                GroupRule::Syscall(syscall_rule) => {
                    children.push(TreeNode::Syscall {
                        rule: syscall_rule.clone(),
                    });
                }
                GroupRule::GroupRef(group_ref) => {
                    if let Some(group_def) = groups.get(&group_ref.group) {
                        children.push(Self::build_tree_node_with_visited(
                            group_ref.group.clone(),
                            group_def.clone(),
                            groups,
                            visited,
                        ));
                    } else {
                        // Unknown group - show as leaf
                        children.push(TreeNode::Group {
                            name: format!("{} (not found)", group_ref.group),
                            children: vec![],
                            expanded: false,
                        });
                    }
                }
            }
        }

        visited.remove(&name);

        TreeNode::Group {
            name,
            children,
            expanded: false,
        }
    }

    fn flatten_visible(&self) -> Vec<(usize, &TreeNode)> {
        let mut result = Vec::new();
        for node in &self.nodes {
            Self::flatten_node(node, 0, &mut result);
        }
        result
    }

    fn flatten_node<'a>(node: &'a TreeNode, depth: usize, result: &mut Vec<(usize, &'a TreeNode)>) {
        result.push((depth, node));
        if node.is_expanded() {
            if let TreeNode::Group { children, .. } = node {
                for child in children {
                    Self::flatten_node(child, depth + 1, result);
                }
            }
        }
    }

    fn next(&mut self) {
        let visible = self.flatten_visible();
        if !visible.is_empty() {
            self.selected = (self.selected + 1).min(visible.len() - 1);
        }
    }

    fn previous(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    fn select(&mut self, index: usize) {
        if index >= self.nodes.len() {
            self.selected = self.nodes.len() - 1;
        } else {
            self.selected = index;
        }
    }

    fn search(&self, query: &str) -> Vec<usize> {
        if query.is_empty() {
            return Vec::new();
        }

        let visible = self.flatten_visible();
        let query_lower = query.to_lowercase();

        visible
            .iter()
            .enumerate()
            .filter(|(_, (_, node))| node.name().to_lowercase().contains(&query_lower))
            .map(|(idx, _)| idx)
            .collect()
    }

    fn select_by_search(&mut self, query: &str) -> bool {
        if query.is_empty() {
            return false;
        }

        let matches = self.search(query);
        if let Some(&first_match) = matches.first() {
            self.selected = first_match;
            true
        } else {
            false
        }
    }

    fn select_by_name(&mut self, name: &str) -> bool {
        let visible = self.flatten_visible();

        for (idx, (_, node)) in visible.iter().enumerate() {
            if node.name() == name {
                self.selected = idx;
                return true;
            }
        }
        false
    }

    fn toggle_selected(&mut self) {
        let visible = self.flatten_visible();
        if visible.get(self.selected).is_some() {
            // We need mutable access to the actual node
            Self::toggle_at_path(&mut self.nodes, self.selected);
        }
    }

    fn toggle_at_path(nodes: &mut [TreeNode], target_idx: usize) {
        let mut current_idx = 0;
        for node in nodes {
            if current_idx == target_idx {
                node.toggle_expand();
                return;
            }
            current_idx += 1;
            if node.is_expanded() {
                if let TreeNode::Group { children, .. } = node {
                    Self::toggle_at_path(children, target_idx - current_idx);
                    // Count visible children
                    current_idx += Self::count_visible(children);
                    if current_idx > target_idx {
                        return;
                    }
                }
            }
        }
    }

    fn count_visible(nodes: &[TreeNode]) -> usize {
        let mut count = 0;
        for node in nodes {
            count += 1;
            if node.is_expanded() {
                if let TreeNode::Group { children, .. } = node {
                    count += Self::count_visible(children);
                }
            }
        }
        count
    }

    /// Expand path to a specific node (useful after search)
    fn expand_to_selection(&mut self) {
        // This ensures the selected node is visible
        // by expanding all parent groups
        let target = self.selected;
        let mut current = 0;
        Self::expand_path_to_index(&mut self.nodes, target, &mut current);
    }

    fn expand_path_to_index(
        nodes: &mut [TreeNode],
        target_idx: usize,
        current_idx: &mut usize,
    ) -> bool {
        for node in nodes {
            if *current_idx == target_idx {
                return true; // Found the target
            }

            *current_idx += 1;

            if let TreeNode::Group {
                expanded, children, ..
            } = node
            {
                if Self::expand_path_to_index(children, target_idx, current_idx) {
                    *expanded = true; // Expand this parent since target is in its subtree
                    return true;
                }
            }
        }
        false
    }

    fn get_selected_node(&self) -> Option<&TreeNode> {
        let visible = self.flatten_visible();
        visible.get(self.selected).map(|(_, node)| *node)
    }

    fn expand_all(&mut self) {
        Self::expand_all_nodes(&mut self.nodes);
    }

    fn expand_all_nodes(nodes: &mut [TreeNode]) {
        for node in nodes {
            if let TreeNode::Group {
                expanded, children, ..
            } = node
            {
                *expanded = true;
                Self::expand_all_nodes(children);
            }
        }
    }

    fn collapse_all(&mut self) {
        Self::collapse_all_nodes(&mut self.nodes);
    }

    fn collapse_all_nodes(nodes: &mut [TreeNode]) {
        for node in nodes {
            if let TreeNode::Group {
                expanded, children, ..
            } = node
            {
                *expanded = false;
                Self::collapse_all_nodes(children);
            }
        }
    }
}

// ============================================================================
// App State
// ============================================================================

struct App {
    mode: AppMode,
    help_visible: bool,
}

enum AppMode {
    Explore {
        tree: TreeState,
        search_mode: bool,
        search_query: String,
    },
    Monitor {
        monitor: SeccompMonitor,
        events: Vec<SeccompEvent>,
        selected: usize,
        auto_scroll: bool,
    },
}

impl App {
    fn new_explore(groups: HashMap<String, AbstractGroupDef>) -> Self {
        Self {
            mode: AppMode::Explore {
                tree: TreeState::new(groups),
                search_mode: false,
                search_query: String::new(),
            },
            help_visible: false,
        }
    }

    fn new_monitor(monitor: SeccompMonitor) -> Self {
        Self {
            mode: AppMode::Monitor {
                monitor,
                events: Vec::new(),
                selected: 0,
                auto_scroll: true,
            },
            help_visible: false,
        }
    }

    fn toggle_help(&mut self) {
        self.help_visible = !self.help_visible;
    }
    fn handle_event(&mut self, event: Event) -> bool {
        // Global keys
        if let Event::Key(key) = event {
            if key.code == KeyCode::Char('q')
                && !matches!(
                    self.mode,
                    AppMode::Explore {
                        search_mode: true,
                        ..
                    }
                )
            {
                return false;
            }
            if key.code == KeyCode::Char('?') || key.code == KeyCode::F(1) {
                self.toggle_help();
                return true;
            }
        }

        // Mode-specific handling - extract references first to avoid borrow issues
        match &mut self.mode {
            AppMode::Explore {
                tree,
                search_mode,
                search_query,
            } => {
                if *search_mode {
                    handle_search_event(event, tree, search_mode, search_query)
                } else {
                    handle_explore_event(event, tree, search_mode, search_query)
                }
            }
            AppMode::Monitor {
                events,
                selected,
                auto_scroll,
                ..
            } => handle_monitor_event(event, events, selected, auto_scroll),
        }
    }

    fn update_monitor(&mut self) {
        if let AppMode::Monitor {
            monitor,
            events,
            selected,
            auto_scroll,
        } = &mut self.mode
        {
            // Collect new events
            while let Some(event) = monitor.try_next_event() {
                events.push(event);
            }

            // Auto-scroll to latest
            if *auto_scroll && !events.is_empty() {
                *selected = events.len() - 1;
            }
        }
    }
}

fn handle_explore_event(
    event: Event,
    tree: &mut TreeState,
    _search_mode: &mut bool,
    search_query: &mut String,
) -> bool {
    if let Event::Key(key) = event {
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => tree.next(),
            KeyCode::Up | KeyCode::Char('k') => tree.previous(),
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => tree.toggle_selected(),
            KeyCode::Left | KeyCode::Char('h') => tree.toggle_selected(),
            KeyCode::Char('G') => tree.select(tree.nodes.len() - 1),
            KeyCode::Char('e') => tree.expand_all(),
            KeyCode::Char('c') => tree.collapse_all(),
            KeyCode::Char('/') => {
                *_search_mode = true;
                search_query.clear();
            }
            _ => {}
        }
    }
    true
}

fn handle_search_event(
    event: Event,
    tree: &mut TreeState,
    search_mode: &mut bool,
    search_query: &mut String,
) -> bool {
    if let Event::Key(key) = event {
        match key.code {
            KeyCode::Esc => {
                *search_mode = false;
                search_query.clear();
            }
            KeyCode::Enter => {
                // Jump to first match and stay in search mode for navigation
                if !search_query.is_empty() {
                    tree.select_by_search(search_query);
                    tree.expand_to_selection();
                }
                *search_mode = false;
            }
            KeyCode::Backspace => {
                search_query.pop();
            }
            _ => {}
        }
    }
    true
}

fn handle_monitor_event(
    event: Event,
    events: &mut Vec<SeccompEvent>,
    selected: &mut usize,
    auto_scroll: &mut bool,
) -> bool {
    if let Event::Key(key) = event {
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                *auto_scroll = false;
                *selected = (*selected + 1).min(events.len().saturating_sub(1));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                *auto_scroll = false;
                if *selected > 0 {
                    *selected -= 1;
                }
            }
            KeyCode::Char('a') => {
                *auto_scroll = !*auto_scroll;
            }
            KeyCode::Char('c') => {
                events.clear();
                *selected = 0;
            }
            KeyCode::Home => {
                *selected = 0;
                *auto_scroll = false;
            }
            KeyCode::End => {
                *selected = events.len().saturating_sub(1);
                *auto_scroll = true;
            }
            _ => {}
        }
    }
    true
}

// ============================================================================
// View Rendering
// ============================================================================

fn render_explore(
    f: &mut Frame,
    tree: &TreeState,
    search_mode: bool,
    search_query: &str,
    help_visible: bool,
) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(f.area());

    render_tree(f, chunks[0], tree, search_mode, search_query);
    render_details(f, chunks[1], tree);

    if help_visible {
        render_help_popup(f);
    }
}

fn render_tree(f: &mut Frame, area: Rect, tree: &TreeState, search_mode: bool, search_query: &str) {
    let visible = tree.flatten_visible();

    let items: Vec<ListItem> = visible
        .iter()
        .map(|(depth, node)| {
            let indent = "  ".repeat(*depth);
            let (icon, style) = match node {
                TreeNode::Group {
                    expanded, children, ..
                } => {
                    if children.is_empty() {
                        ("○ ", Style::default().fg(Color::DarkGray))
                    } else if *expanded {
                        ("▼ ", Style::default().fg(Color::Yellow))
                    } else {
                        ("▶ ", Style::default().fg(Color::Cyan))
                    }
                }
                TreeNode::Syscall { .. } => ("  • ", Style::default().fg(Color::Green)),
            };

            let text = format!("{}{}{}", indent, icon, node.name());
            ListItem::new(text).style(style)
        })
        .collect();

    let title = if search_mode {
        format!("Abstract Rules (Search: {}█)", search_query)
    } else {
        "Abstract Rules (? for help)".to_string()
    };

    let list = List::new(items)
        .block(Block::default().title(title).borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(Color::DarkGray),
        )
        .highlight_symbol(">> ");

    let mut list_state = ListState::default();
    list_state.select(Some(tree.selected));

    f.render_stateful_widget(list, area, &mut list_state);
}

fn render_details(f: &mut Frame, area: Rect, tree: &TreeState) {
    let content = if let Some(node) = tree.get_selected_node() {
        match node {
            TreeNode::Group { name, children, .. } => {
                let mut text = format!("📁 Group: {}\n\n", name);
                text.push_str(&format!("Children: {}\n\n", children.len()));

                if !children.is_empty() {
                    text.push_str("Contents:\n");
                    for child in children {
                        match child {
                            TreeNode::Group { name, .. } => {
                                text.push_str(&format!("  📁 {}\n", name));
                            }
                            TreeNode::Syscall { rule } => {
                                text.push_str(&format!("  • {}\n", rule.name));
                            }
                        }
                    }
                }
                text
            }
            TreeNode::Syscall { rule } => {
                let mut text = format!("🔧 Syscall: {}\n\n", rule.name);

                if rule.conditions.is_empty() {
                    text.push_str("No conditions (unrestricted)\n");
                } else {
                    text.push_str("Conditions:\n");
                    for (i, condition) in rule.conditions.iter().enumerate() {
                        text.push_str(&format!("\n{}. Type: {}\n", i + 1, condition.type_));
                        text.push_str(&format!("   Argument: {}\n", condition.argument));

                        if let Some(value) = &condition.value {
                            text.push_str(&format!("   Value: {}\n", value));
                        }

                        if let Some(flags) = &condition.flags {
                            text.push_str(&format!("   Flags: {}\n", flags));
                        }
                    }
                }
                text
            }
        }
    } else {
        "No selection".to_string()
    };

    let paragraph = Paragraph::new(content)
        .block(Block::default().title("Details").borders(Borders::ALL))
        .wrap(Wrap { trim: true });

    f.render_widget(paragraph, area);
}

fn render_monitor(
    f: &mut Frame,
    events: &[SeccompEvent],
    selected: usize,
    auto_scroll: bool,
    help_visible: bool,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(8),
        ])
        .split(f.area());

    // Status bar
    let status = Paragraph::new(format!(
        "Events: {} | Auto-scroll: {} | Press 'a' to toggle, 'c' to clear, '?' for help",
        events.len(),
        if auto_scroll { "ON" } else { "OFF" }
    ))
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(status, chunks[0]);

    // Event list
    let items: Vec<ListItem> = events
        .iter()
        .enumerate()
        .map(|(i, event)| {
            let fatal = if event.is_fatal() { " [FATAL]" } else { "" };
            let text = format!(
                "{}: {} - {} - {}{}",
                i + 1,
                event.comm,
                event.syscall_name(),
                event.decoded_summary(),
                fatal
            );
            let style = if event.is_fatal() {
                Style::default().fg(Color::Red)
            } else {
                Style::default()
            };
            ListItem::new(text).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().title("Events").borders(Borders::ALL))
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .bg(Color::DarkGray),
        );

    let mut list_state = ListState::default();
    list_state.select(Some(selected));

    f.render_stateful_widget(list, chunks[1], &mut list_state);

    // Detail panel
    if let Some(event) = events.get(selected) {
        let detail = format!(
            "Timestamp: {}\nProcess: {} (PID: {})\nExecutable: {}\nSyscall: {}({})\nAction: {}\nUser: uid={}, gid={}\nIP: {}",
            event.timestamp,
            event.comm,
            event.pid,
            event.exe,
            event.syscall_name(),
            event.syscall,
            event.decoded_summary(),
            event.uid,
            event.gid,
            event.ip
        );

        let paragraph = Paragraph::new(detail)
            .block(Block::default().title("Event Detail").borders(Borders::ALL))
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, chunks[2]);
    }

    if help_visible {
        render_help_popup(f);
    }
}

fn render_help_popup(f: &mut Frame) {
    let area = centered_rect(60, 60, f.area());

    let help_text = vec![
        "Keyboard Shortcuts",
        "",
        "Global:",
        "  q         - Quit",
        "  ?/F1      - Toggle this help",
        "",
        "Explore Mode:",
        "  ↑/k       - Move up",
        "  ↓/j       - Move down",
        "  Enter/→/l - Expand/collapse",
        "  ←/h       - Collapse",
        "  e         - Expand all",
        "  c         - Collapse all",
        "  /         - Search",
        "",
        "Monitor Mode:",
        "  ↑/k       - Previous event",
        "  ↓/j       - Next event",
        "  a         - Toggle auto-scroll",
        "  c         - Clear events",
        "  Home      - First event",
        "  End       - Last event",
        "",
        "Press ? again to close",
    ];

    let text = help_text.join("\n");
    let paragraph = Paragraph::new(text)
        .block(
            Block::default()
                .title("Help")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .wrap(Wrap { trim: true })
        .style(Style::default().bg(Color::Black));

    f.render_widget(Clear, area);
    f.render_widget(paragraph, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

// ============================================================================
// Public API
// ============================================================================

pub fn run_explore_tui() -> Result<()> {
    let groups = load_abstract_groups()?;
    let app = App::new_explore(groups);
    run_app(app)
}

pub fn run_monitor_tui(mut monitor: SeccompMonitor) -> Result<()> {
    monitor.start().map_err(|_| {
        TuiError::Profile(ProfileError::Action(
            crate::actions::ActionError::UnknownAction,
        ))
    })?;

    let app = App::new_monitor(monitor);
    run_app(app)
}

fn run_app(mut app: App) -> Result<()> {
    let mut terminal = ratatui::init();
    terminal.clear()?;

    let result = run_event_loop(&mut terminal, &mut app);

    ratatui::restore();

    result
}

fn run_event_loop(terminal: &mut Terminal<impl Backend>, app: &mut App) -> Result<()> {
    loop {
        // Update monitor if in monitor mode
        app.update_monitor();

        // Draw UI
        terminal.draw(|f| match &app.mode {
            AppMode::Explore {
                tree,
                search_mode,
                search_query,
            } => {
                render_explore(f, tree, *search_mode, search_query, app.help_visible);
            }
            AppMode::Monitor {
                events,
                selected,
                auto_scroll,
                ..
            } => {
                render_monitor(f, events, *selected, *auto_scroll, app.help_visible);
            }
        })?;

        // Handle events with timeout (for monitor updates)
        if event::poll(Duration::from_millis(100))? {
            let event = event::read()?;
            if !app.handle_event(event) {
                break;
            }
        }
    }

    Ok(())
}

pub fn run_exec_with_tui(
    ctx: ScmpFilterContext,
    path: Vec<String>,
    pass_env: bool,
    show_all: bool,
) -> Result<()> {
    use crate::commands::{
        apply_seccomp_filter, build_command, execute_with_tui_monitoring, export_bpf_filter,
    };

    let bpf_bytes = export_bpf_filter(&ctx).map_err(|_| {
        TuiError::Profile(ProfileError::Action(
            crate::actions::ActionError::UnknownAction,
        ))
    })?;

    let mut command = build_command(&path, pass_env);
    apply_seccomp_filter(&mut command, bpf_bytes);

    let (status, monitor) = execute_with_tui_monitoring(command).map_err(|_| {
        TuiError::Profile(ProfileError::Action(
            crate::actions::ActionError::UnknownAction,
        ))
    })?;

    run_monitor_tui(monitor)?;

    // Handle final status
    if !status.success() {
        return Err(TuiError::Profile(ProfileError::Action(
            crate::actions::ActionError::UnknownAction,
        )));
    }

    Ok(())
}

