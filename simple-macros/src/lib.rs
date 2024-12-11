extern crate proc_macro;
use proc_macro::TokenStream;
use std::any::Any;
use std::cmp::min;
use std::str::FromStr;
use quote::{quote, ToTokens, TokenStreamExt};
use syn::{parse_macro_input, Attribute, Data, Expr, Fields, Lit, Meta, ReturnType, Token};
use syn::parse::Parse;

// TODO this shouldn't require the from type to derive clone
// TODO I want this to take an attr argument to control whether we generate FromIterator or not
#[proc_macro_attribute]
pub fn from(attr: TokenStream, item: TokenStream) -> TokenStream {
  let ast = syn::parse::<syn::ItemFn>(item).expect("The #[from] macro can only be applied to free-standing functions");

  if ast.sig.inputs.len() != 1 || ast.sig.output == ReturnType::Default {
    panic!("#[from] requires annotated function to have form fn (X) -> Y where X is any type and Y is a non-void type.");
  }

  let attributes = ast.attrs.into_iter()
    .filter(|attr| match &attr.meta {
      Meta::Path(path) if path.is_ident("from") => false,
      Meta::Path(path) if path.segments.len() == 1 => match path.segments.last() {
        Some(segment) if segment.ident.to_string() == "from" => false,
        _ => true
      }
      Meta::List(list) if list.path.is_ident("from") => false,
      Meta::List(list) if list.path.segments.len() == 1 => match list.path.segments.last() {
        Some(segment) if segment.ident.to_string() == "from" => false,
        _ => true
      }
      _ => true
    })
    .collect::<Vec<Attribute>>();
    
  let to_type = match ast.sig.output {
    ReturnType::Type(_, return_type) => return_type,
    ReturnType::Default => panic!("We need a return type :(")
  };
  let (from_arg_name, from_type) = match ast.sig.inputs.get(0) {
    Some(syn::FnArg::Typed(base_arg)) => {
      (base_arg.pat.clone(), base_arg.ty.clone())
    }
    _ => panic!("Bad function argument!! Must be 1 non-receiver argument")
  };

  let function_body = ast.block.stmts;

  let generated = quote! {
    #(#attributes)*
    impl From<#from_type> for #to_type {
      fn from(#from_arg_name: #from_type) -> Self {
        #(#function_body)*
      }
    }

    #(#attributes)*
    impl From<&#from_type> for #to_type {
      fn from(#from_arg_name: &#from_type) -> Self {
        #from_arg_name.clone().into()
      }
    }

    #(#attributes)*
    impl FromIterator<#from_type> for Vec<#to_type> {
      fn from_iter<T: IntoIterator<Item = #from_type>>(iter: T) -> Self {
        iter.into_iter().collect()
      }
    }

    #(#attributes)*
    impl<'from_iterator_lifetime> FromIterator<&'from_iterator_lifetime #from_type> for Vec<#to_type> {
      fn from_iter<T: IntoIterator<Item = &'from_iterator_lifetime #from_type>>(iter: T) -> Self {
        iter.into_iter().map(|x| <#from_type as Into<#to_type>>::into(x.clone())).collect()
      }
    }
  };
  generated.into()
}