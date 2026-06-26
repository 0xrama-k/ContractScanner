//! Solidity preprocessing (Section 5): extract lightweight contract metadata.
//!
//! This is a best-effort textual scan, not a full parser. Slither remains the
//! authority on compilation; this only feeds the UI/LLM/report and import hints.

#![allow(dead_code)]

use once_cell::sync::Lazy;
use regex::Regex;

use crate::models::metadata::ContractMetadata;
use crate::util;

static PRAGMA_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"pragma\s+solidity\s+([^;]+);").unwrap());

// contract / library / interface / abstract contract <Name>
static TYPE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)\b(?:abstract\s+)?(?:contract|library|interface)\s+([A-Za-z_]\w*)").unwrap()
});

static FUNCTION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bfunction\s+([A-Za-z_]\w*)").unwrap());

// import "...";  |  import {A} from "...";  |  import * as X from "...";
static IMPORT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"import\s+[^;]*?["']([^"']+)["']"#).unwrap());

pub fn extract(filename: &str, source: &str) -> ContractMetadata {
    let pragma = PRAGMA_RE
        .captures(source)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string());

    let contracts = dedup_in_order(TYPE_RE.captures_iter(source).map(|c| c[1].to_string()));
    let functions = dedup_in_order(FUNCTION_RE.captures_iter(source).map(|c| c[1].to_string()));
    let imports = dedup_in_order(IMPORT_RE.captures_iter(source).map(|c| c[1].to_string()));

    ContractMetadata {
        filename: filename.to_string(),
        language: "Solidity".to_string(),
        pragma,
        contracts,
        functions,
        imports,
        unresolved_imports: Vec::new(), // filled by the Slither step if compilation fails
        line_count: source.lines().count(),
        source_hash: util::sha256_hex(source),
    }
}

fn dedup_in_order<I: Iterator<Item = String>>(iter: I) -> Vec<String> {
    let mut seen = Vec::new();
    for item in iter {
        if !seen.contains(&item) {
            seen.push(item);
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Vault is Ownable {
    function deposit() public payable {}
    function withdraw(uint256 amount) public {}
    function setFee(uint256 fee) external onlyOwner {}
}

interface IVault {
    function deposit() external;
}
"#;

    #[test]
    fn extracts_pragma_contracts_functions_imports() {
        let md = extract("Vault.sol", SAMPLE);
        assert_eq!(md.pragma.as_deref(), Some("^0.8.20"));
        assert_eq!(md.contracts, vec!["Vault".to_string(), "IVault".to_string()]);
        // dedup: deposit appears twice (contract + interface) -> once
        assert_eq!(
            md.functions,
            vec![
                "deposit".to_string(),
                "withdraw".to_string(),
                "setFee".to_string()
            ]
        );
        assert_eq!(
            md.imports,
            vec![
                "@openzeppelin/contracts/access/Ownable.sol".to_string(),
                "@openzeppelin/contracts/token/ERC20/IERC20.sol".to_string()
            ]
        );
        assert!(md.unresolved_imports.is_empty());
        assert!(md.source_hash.starts_with("sha256:"));
        assert_eq!(md.language, "Solidity");
    }

    #[test]
    fn handles_source_without_pragma() {
        let md = extract("Lib.sol", "library Math { function add() internal {} }");
        assert!(md.pragma.is_none());
        assert_eq!(md.contracts, vec!["Math".to_string()]);
    }
}
