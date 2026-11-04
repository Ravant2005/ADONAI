# ADONAI — Pilot Installation & Testing Guide

## 1. One-Command Mac/Linux Backend & 3D Lab Launch
```bash
unzip ADONAI_Complete_Product.zip
cd ADONAI
./scripts/start_mac_lab.sh
```
- Open **`http://127.0.0.1:8410`** for the 12-view Mac Intelligence & 3D Cyber-Range Dashboard.
- Open **`http://127.0.0.1:8410/mobile`** for the interactive 12-screen Android Companion Simulator.

## 2. Run Full Automated Verification & Ground-Truth Benchmark
```bash
./scripts/run_tests_and_benchmarks.sh
```

## 3. Native Android Agent (`android-agent/`)
Open `android-agent/` in Android Studio Ladybug (or newer) with JDK 17 and Android SDK 35, set your Mac LAN IP in the pairing screen, and run on an Android 10+ device or emulator.
