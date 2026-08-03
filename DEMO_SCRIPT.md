# VulnGraph & TDRA 5-Minute Demo Script

Follow these steps for a complete, zero-downtime, offline-ready live demonstration of VulnGraph's Differential Analysis Engine.

---

### Step 1: Initialize the Demo Environment (30 seconds)
Launch the unified server infrastructure and pre-warm the analysis cache:
```bash
bash scripts/run_demo.sh
```
* **Speaker Script**: *"I am launching the VulnGraph demo. This script automatically cleans up binding ports, fires up the FastAPI backend and Vite frontend, and pre-warms the security engine by scanning our target `demo_project` codebase."*

---

### Step 2: Show the 3D Program Graph (30 seconds)
Observe the automatically loaded graph at `http://localhost:5173`:
1. Use the mouse to rotate and zoom into the 3D code-network graph.
2. Point out the color-coded nodes: **ENTRY (Green)**, **SINK (Red)**, and **GUARD (Purple)**.
* **Speaker Script**: *"As the browser opens, we are presented with an interactive, 3D interprocedural code property graph of our scanned codebase. You can see our data-flow inputs in green, sanitizers and guards in purple, and sensitive sinks in red."*

---

### Step 3: Inspect the Riskiest Sink Node (30 seconds)
1. Hover over a **Red (Sink)** node in the 3D canvas (e.g. `runQuery()` or `execute()`).
2. Click the node to expand the details card in the **🔍 Node Info** sidebar tab.
3. Review the **Git Blame** metadata (Author, Commit date, Hash).
* **Speaker Script**: *"Clicking on this critical database query sink immediately displays its taint propagation metrics. In the right panel, we see git-attribution metadata directly associating this line with its author and date of introduction, allowing us to see who added the sink."*

---

### Step 4: Open Commit Risk Timeline (1 minute)
1. Transition to the **⏰ Timeline** tab in the sidebar.
2. Click the commit with the highest RF score (e.g., *`a7d0c9b...` "feat: add dynamic report export using eval()"*, RF = `0.8200`).
* **Speaker Script**: *"Now, I'll switch to the Commit Risk Timeline. We see a history of code revisions ranked by our temporal risk factor. I'll click the riskiest commit, which introduced a dynamic template evaluation sink using eval()."*

---

### Step 5: Explore Differential Visualization Mode (1 minute)
1. Look at the 3D Graph Canvas which has now entered **Diff Mode** (highlighting new/modified components).
2. Point out the newly introduced red paths showing the data flow into the dynamic sink.
3. Show how the bypassed/removed guard nodes are displayed as faded, hollow shells.
* **Speaker Script**: *"VulnGraph has entered Diff Mode. The canvas highlights only the new taint paths introduced by this specific commit. The bypassed guard node `sanitize_template` is visible as a faded, hollow ring, indicating that this change actively bypassed a security control."*

---

### Step 6: VS Code Extension Inline Decorations (30 seconds)
1. Open the vscode-extension directory and install the extension:
   ```bash
   bash vscode-extension/install.sh
   ```
2. Open a Python/Java file in VS Code and show the inline entry/sink/guard color indicators.
* **Speaker Script**: *"We also pack this analysis into an IDE extension. Running our install script compiles the local VSIX file and loads it into VS Code. When opening a file, developers receive inline green, red, and purple decorations on entries, sinks, and guards, running 100% locally."*

---

### Step 7: Export Executive HTML Report (1 minute)
1. Click **📊 Download Report** in the web interface and open the HTML report.
2. Scroll through the Executive Summary, SVG RF score histogram, and Remediation Recommendations.
* **Speaker Script**: *"I'll download the executive HTML report. It generates a complete security audit, including an SVG histogram mapping the project's risk trajectory over time, detailed remediation guidance for command/SQL/file sinks, and our statistical validation results."*

---

### Step 8: Statistical Validation Panel (30 seconds)
1. Click the **📊 Validate** tab in the Right Panel.
2. View the Mann-Whitney U test results.
* **Speaker Script**: *"Lastly, in the Validate tab, we run a Mann-Whitney U test comparing our VCC and non-VCC cohorts. Our algorithm achieves a p-value of 0.039 and a Cliff's delta of 0.75. This mathematically proves that our Risk Factor metric separates vulnerability-introducing commits from safe commits with a statistically significant, large effect size."*
