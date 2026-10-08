//! Syntax-based physical function length inventory; cfg(test) items are excluded.
use std::{env, fs, path::Path};
use syn::{Attribute, spanned::Spanned, visit::Visit};

fn test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|s| s.ident == "test")
            || (attr.path().is_ident("cfg")
                && attr
                    .parse_args::<syn::Path>()
                    .is_ok_and(|p| p.is_ident("test")))
    })
}

struct Inventory<'a> {
    path: &'a Path,
}
impl Inventory<'_> {
    fn record(&self, name: &syn::Ident, span: proc_macro2::Span) {
        let start = span.start().line;
        let end = span.end().line;
        let count = end - start + 1;
        if count >= 50 {
            println!("{}\t{}\t{}\t{}", self.path.display(), name, start, count);
        }
    }
}
impl<'ast> Visit<'ast> for Inventory<'_> {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !test_only(&item.attrs) && item.ident != "tests" {
            syn::visit::visit_item_mod(self, item);
        }
    }
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !test_only(&item.attrs) {
            self.record(
                &item.sig.ident,
                item.sig.span().join(item.block.span()).unwrap(),
            );
            syn::visit::visit_item_fn(self, item);
        }
    }
    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if !test_only(&item.attrs) {
            syn::visit::visit_item_impl(self, item);
        }
    }
    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if !test_only(&item.attrs) {
            self.record(
                &item.sig.ident,
                item.sig.span().join(item.block.span()).unwrap(),
            );
            syn::visit::visit_impl_item_fn(self, item);
        }
    }
    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if !test_only(&item.attrs) {
            if let Some(block) = &item.default {
                self.record(&item.sig.ident, item.sig.span().join(block.span()).unwrap());
            }
            syn::visit::visit_trait_item_fn(self, item);
        }
    }
}

fn scan(path: &Path) {
    if path.is_dir() {
        let mut entries: Vec<_> = fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for entry in entries {
            scan(&entry);
        }
    } else if path.extension().is_some_and(|ext| ext == "rs")
        && path.file_name().is_some_and(|name| {
            name != "tests.rs" && !name.to_string_lossy().ends_with("_test_support.rs")
        })
    {
        let source = fs::read_to_string(path).unwrap();
        let file = syn::parse_file(&source).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        Inventory { path }.visit_file(&file);
    }
}

fn main() {
    for root in env::args().skip(1) {
        scan(Path::new(&root));
    }
}
