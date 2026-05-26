# dros-core-rs (DROS Rust Micro-Kernel)

<div align="center">

**The Official Reference Implementation of the DROS-RFC-001 Architecture Specification**

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0.html)
[![Language: Rust](https://img.shields.io/badge/Language-Rust-informational.svg)]()
[![Official Website](https://img.shields.io/badge/Official-dr--os.io-gold.svg)](https://dr-os.io)
[![Documentation](https://img.shields.io/badge/Docs-Read-blue.svg)](https://dr-os.io/docs)

<br/>
<br/>
</div>

> *High-performance, memory-safe Dharma Reasoning Micro-Kernel.*

This repository contains the authoritative **Rust** implementation of the **[Dharma Reasoning Operating System (DROS)](https://dr-os.io)** Micro-Kernel. 

As the original creators of the DROS Architecture, this codebase serves as the absolute standard for deterministic, hallucination-free reasoning engines designed for Large Language Models (LLMs).

---

## 🌐 Ecosystem Overview

DROS is composed of two primary layers:

1. **The Open-Source Core (This Repository):**
   This is the fundamental reasoning engine. It implements the strict constraints and deterministic logic routing of the `DROS-RFC-001` Specification. It is 100% open-source under the AGPL-3.0 license.

2. **The Commercial Guard (VajraClaw):**
   For enterprise and proprietary deployments, we offer [**VajraClaw**](https://github.com/Top-Celestial-Company-Ltd/VajraClaw), our physical-layer C-FFI Circuit Breaker. VajraClaw seamlessly wraps around this open-source core, providing anti-tamper UUID binding and commercial licensing exemptions without requiring your entire enterprise application to be open-sourced. 
   👉 **[Learn more about Commercial Licensing](https://dr-os.io/pricing)**

---

## 🏛 The Technical Whitepaper & Specification

This repository is governed by the **DROS-RFC-001 Specification**. 
Any implementation claiming to be DROS-compliant must adhere to the structural constraints laid out in our official whitepapers.

- **Protocol**: Fully compliant with `DROS-RFC-001` Semantic Constraints.
- **Architecture**: Minimalist footprint, zero-dependency core logic designed for Absolute Truth mapping.
- **Integration**: Plugs directly into your Rust-based architectures to act as the cognitive firewall for LLMs.

---

## 🚀 Quick Start

**1. Installation & Build**
```bash
cargo build --release
cargo test
```

**2. Execution**
```bash
cargo run --release
```

For complete integration tutorials and API references, please visit our **[Official Documentation](https://dr-os.io/docs)**.

---

## ⚖️ Legal Boundaries & Intellectual Property (Strict Compliance)

**Our technological authority is protected by strict Copyright and Open Source Licensing.** 
This software is governed by the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

> **WARNING**: DROS is a highly protected intellectual property. The AGPL-3.0 license is intentionally utilized as a legal shield to enforce open-source compliance for all networked applications.

1. **Networked Usage (SaaS / API)**: If you wrap this micro-kernel inside a server, API, web application, or SaaS offering, you **MUST** open-source the complete corresponding source code of your entire application stack under AGPL-3.0.
2. **Proprietary Commercialization**: This kernel **CANNOT** be closed-source or integrated into proprietary/commercial systems without a separate **Commercial License** from the original creators. If you need this, you must procure **VajraClaw**.
3. **No "Soft" Exceptions**: We do not recognize "internal enterprise use" as an exemption if the service interfaces with public networks. Any obfuscation, bypassing of license constraints, or stripping of original authorship attribution is a direct violation of international copyright law.

For commercial inquiries and proprietary licensing, please [visit our website](https://dr-os.io/pricing).

---
<div align="center">
  <br/>
  <b>Save EVERYTHING. Buy the Vajra Claw.</b><br/>
  <a href="https://dr-os.io">dr-os.io</a>
</div>
