use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{parse::Parser, LitStr};

#[proc_macro]
pub fn include_bytes_or(input: TokenStream) -> TokenStream {
    let parser = syn::punctuated::Punctuated::<LitStr, syn::Token![,]>::parse_terminated;
    let paths: syn::punctuated::Punctuated<LitStr, syn::Token![,]> =
        match parser.parse(input.clone()) {
            Ok(p) => p,
            Err(e) => return e.to_compile_error().into(),
        };

    for lit_str in paths {
        let path = lit_str.value();

        if std::path::Path::new(&path).exists() {
            // Use the absolute path
            let abs_path = std::fs::canonicalize(&path).expect("Failed to canonicalize path");
            let abs_str = abs_path.to_str().expect("Invalid path");

            let path_literal = proc_macro2::Literal::string(abs_str);
            return quote! {
                include_bytes!(#path_literal)
            }
            .into();
        }
    }

    let error = syn::Error::new(Span::call_site(), "None of the provided paths exist");
    error.to_compile_error().into()
}
