# 🚀 Production Promotion GO/NO-GO Assessment Tool - Setup Complete

## ✅ Files Created

### Main Script
- **`production_promotion_check.py`** (33 KB)
  - Full-featured GO/NO-GO decision engine
  - Supports Evaluate and Compare modes
  - Color-coded console output
  - Machine-readable output for CI/CD
  - Comprehensive logging

### Configuration Examples
- **`config_evaluate_example.yaml`** (1.3 KB)
  - Template for standalone assessment
  - Management Zone and Host List modes
  
- **`config_compare_example.yaml`** (2.6 KB)
  - Template for comparative assessment
  - Separate configs for cert and prod environments

### Documentation
- **`PRODUCTION_PROMOTION_GUIDE.md`** (16 KB)
  - Comprehensive user guide
  - Decision logic details
  - Integration examples (Jenkins, GitHub Actions, GitLab)
  - Troubleshooting section
  
- **`QUICKSTART.md`** (2.2 KB)
  - Quick reference guide
  - Common commands
  - CI/CD snippets

### Updated Dependencies
- **`requirements.txt`**
  - Added `pyyaml>=6.0.2,<7.0.0` for YAML config parsing

## 📋 Key Features Implemented

### ✓ Dual Assessment Modes
- **Evaluate Mode**: Standalone certification environment assessment
- **Compare Mode**: Certification vs Production comparison with regression detection

### ✓ Flexible Scoping Options
- **Management Zone Mode**: Filter by Dynatrace Management Zones
- **Host List Mode**: Filter by specific host IDs
- Mix and match between environments

### ✓ Comprehensive Decision Logic
```
GO Decision:
  ✓ No CRITICAL/HIGH vulnerabilities
  ✓ No vulnerable functions in use
  ✓ Vulnerable function usage assessable
  ✓ [Compare] No regression vs production

NO-GO Decision:
  ✗ Any CRITICAL/HIGH vulnerabilities
  ✗ Any vulnerable function in use
  ✗ Cannot assess vulnerable function usage
  ✗ [Compare] Regression detected
```

### ✓ Comparative Analysis (Compare Mode)
- Detects new vulnerabilities introduced
- Identifies resolved vulnerabilities
- Checks for severity regressions
- Monitors vulnerable function usage changes

### ✓ Rich Console Output
- Color-coded vulnerability digest (Red names, Orange scores)
- Clear GO/NO-GO decision display
- Progress indicators during execution
- Detailed reasoning for decisions

### ✓ Multiple Report Formats
- **JSON**: Detailed hierarchical structure with full metadata
- **CSV**: Flat format for spreadsheet analysis
- **Machine-readable**: Simple GO/NO-GO for automation

### ✓ Advanced Logging
- File logging to `production_promotion_check.log`
- Optional verbose mode (`-v`) for detailed console output
- All API calls and decisions logged

### ✓ CI/CD Integration Ready
- Exit codes: 0 (GO), 1 (NO-GO), 2 (Error)
- Machine-readable flag for pipelines
- Examples for Jenkins, GitHub Actions, GitLab CI

## 🎯 Decision Tree Implemented

```
Start
  │
  ├─> Fetch Certification Vulnerabilities
  │
  ├─> Check CRITICAL/HIGH? ──Yes──> [NO-GO]
  │                          │
  │                          No
  │                          │
  ├─> Check Vulnerable Functions (IN_USE/NOT_AVAILABLE)? ──Yes──> [NO-GO]
  │                                                        │
  │                                                        No
  │                                                        │
  ├─> Compare Mode?
  │       │
  │       No ──────────────────────────────────────────> [GO]
  │       │
  │       Yes
  │       │
  │       ├─> Fetch Production Vulnerabilities
  │       │
  │       ├─> Compare Environments
  │       │     - New vulnerabilities?
  │       │     - Severity regressions?
  │       │     - Function usage regressions?
  │       │
  │       ├─> Regression Detected? ──Yes──> [NO-GO]
  │                                  │
  │                                  No
  │                                  │
  └───────────────────────────────> [GO]
```

## 🔧 Installation & Setup

### 1. Install Dependencies
```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
# venv\Scripts\activate   # On Windows

# Install requirements
pip install -r requirements.txt
```

### 2. Create Your Configuration
```bash
# For standalone assessment
cp config_evaluate_example.yaml my_config.yaml

# For comparative assessment
cp config_compare_example.yaml my_config.yaml
```

### 3. Edit Configuration
Update your config file with:
- Dynatrace tenant URL(s)
- API tokens (with `securityProblems.read` and `entities.read` permissions)
- Management zones or host IDs

### 4. Run Assessment
```bash
python production_promotion_check.py -c my_config.yaml
```

## 📊 Usage Examples

### Basic Assessment
```bash
python production_promotion_check.py -c config_evaluate.yaml
```

### Comparative Assessment with CSV
```bash
python production_promotion_check.py -c config_compare.yaml -f csv -o report.csv
```

### CI/CD Pipeline
```bash
# Machine-readable output
python production_promotion_check.py -c config.yaml -m

# Use exit code
if [ $? -eq 0 ]; then
    echo "✅ GO: Promoting to production"
    # Deploy to production
else
    echo "❌ NO-GO: Blocking deployment"
    exit 1
fi
```

### Verbose Debugging
```bash
python production_promotion_check.py -c config.yaml -v
```

## 🎨 Console Output Preview

```
=== Production Promotion Assessment ===
Mode: COMPARE
Time: 2025-12-04 14:30:00

Fetching vulnerabilities from certification_environment...
  → Found 12 vulnerabilities

Fetching vulnerabilities from production_environment...
  → Found 15 vulnerabilities

Comparing Certification vs Production...
  New vulnerabilities: 2
  Resolved vulnerabilities: 5
  Common vulnerabilities: 10
  Severity regression: False
  Vulnerable function regression: False

=== Decision Analysis ===

Certification Environment:
  Total vulnerabilities: 12
  Critical/High severity: 0
  Vulnerable functions in use: 0

Vulnerability Digest:

  • CVE-2024-12345: Remote Code Execution
    Davis Security Score: 7.5 | Severity: MEDIUM
    Vulnerable Function: NOT_IN_USE

Comparative Analysis:
  Regression detected: True

============================================================
DECISION: NO-GO ✗
============================================================

✗ NO-GO Decision: The certification environment does not meet criteria...
  Reasons:
    - Introduced 2 new vulnerabilities compared to production

Report generated: report_20251204_143000.json
```

## 📁 Report Examples

### JSON Report Structure
```json
{
  "assessment_info": {
    "mode": "compare",
    "decision": "GO",
    "timestamp": "2025-12-04T14:30:00"
  },
  "certification_environment": {
    "total_vulnerabilities": 12,
    "vulnerabilities": [...]
  },
  "production_environment": {...},
  "comparison": {
    "new_vulnerabilities_count": 0,
    "severity_regression": false
  },
  "decision_details": {...}
}
```

### CSV Report
Flat structure with columns:
- Environment, CVE_ID, Title, Risk_Level, Risk_Score
- Vulnerable_Function_Usage, Technology, Package_Name
- Affected_Entities, Management_Zones, Status

## 🔐 API Token Setup

Required Dynatrace API permissions:
- `securityProblems.read` - Read security problems
- `entities.read` - Read entities

Create token at: **Settings > Integration > Dynatrace API**

## 📖 Documentation

- **Full Guide**: `PRODUCTION_PROMOTION_GUIDE.md`
- **Quick Start**: `QUICKSTART.md`
- **Help Command**: `python production_promotion_check.py -h`

## 🚦 Exit Codes

- **0**: GO - Application ready for production
- **1**: NO-GO - Application NOT ready for production  
- **2**: Error - Configuration or execution error

## ✨ Additional Features

### Suggested Comparative Checks Implemented
1. ✅ New vulnerabilities introduced
2. ✅ Severity regressions (vulnerabilities becoming more severe)
3. ✅ Vulnerable function usage regressions
4. ✅ Resolved vulnerabilities tracking

### Logging Capabilities
- ✅ In-depth logging at each step (verbose mode)
- ✅ File logging to `production_promotion_check.log`
- ✅ API call tracking
- ✅ Decision logic visibility

### Report Features
- ✅ Complete vulnerability metadata
- ✅ Affected hosts and processes as separate fields
- ✅ Management zone associations
- ✅ Risk assessment details
- ✅ Timestamps (first seen, last updated)

## 🎓 Next Steps

1. **Install dependencies** in a virtual environment
2. **Create your configuration** from the examples
3. **Test with evaluate mode** first
4. **Try compare mode** for full regression analysis
5. **Integrate into CI/CD** pipeline
6. **Customize** decision criteria if needed

## 💡 Tips

- Use **Management Zones** for logical application grouping
- Store **API tokens** in environment variables or secret managers
- Run assessments **before** production deployments
- Keep **configuration files** in version control (without tokens)
- Archive **reports** for compliance and audit trails
- Enable **verbose mode** when troubleshooting

## 🎉 You're Ready!

The Production Promotion GO/NO-GO Assessment Tool is fully configured and ready to use. 

Start with the **QUICKSTART.md** for immediate usage, or dive into **PRODUCTION_PROMOTION_GUIDE.md** for comprehensive documentation.

Happy assessing! 🚀
