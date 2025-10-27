#!/usr/bin/env python3
import sys
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QTextEdit, 
    QVBoxLayout, QHBoxLayout, QWidget, QPushButton,
    QLineEdit, QLabel, QMessageBox
)
from PyQt6.QtGui import QFont, QColor, QPalette


class ResultViewer(QMainWindow):
    def __init__(self, results_dir="results"):
        super().__init__()
        self.results_dir = Path(results_dir)
        self.results = {}
        self.text_widgets = {}
        self.original_contents = {}
        
        self.init_ui()
        self.load_results()
        
    def init_ui(self):
        self.setWindowTitle("APK Analysis Results")
        self.setGeometry(100, 100, 1200, 800)
        
        # Dark theme
        self.set_dark_theme()
        
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        
        # Top bar with controls
        top_bar = QHBoxLayout()
        
        # Search box
        search_label = QLabel("Search:")
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Filter results...")
        self.search_box.textChanged.connect(self.filter_current_tab)
        
        # Buttons
        copy_btn = QPushButton("Copy Tab")
        copy_btn.clicked.connect(self.copy_current_tab)
        
        clear_btn = QPushButton("Clear Filter")
        clear_btn.clicked.connect(self.clear_filter)
        
        open_btn = QPushButton("Open Results Dir")
        open_btn.clicked.connect(self.open_results_dir)
        
        top_bar.addWidget(search_label)
        top_bar.addWidget(self.search_box, stretch=1)
        top_bar.addWidget(clear_btn)
        top_bar.addWidget(copy_btn)
        top_bar.addWidget(open_btn)
        
        layout.addLayout(top_bar)
        
        # Tab widget
        self.tabs = QTabWidget()
        self.tabs.currentChanged.connect(self.on_tab_changed)
        layout.addWidget(self.tabs)
        
        # Status bar
        self.statusBar().showMessage("Ready")
        
    def set_dark_theme(self):
        """Apply dark theme"""
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor(30, 30, 30))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(212, 212, 212))
        palette.setColor(QPalette.ColorRole.Base, QColor(25, 25, 25))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(45, 45, 48))
        palette.setColor(QPalette.ColorRole.Text, QColor(212, 212, 212))
        palette.setColor(QPalette.ColorRole.Button, QColor(45, 45, 48))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(212, 212, 212))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(0, 122, 204))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
        
        self.setPalette(palette)
        
        self.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #3e3e42;
                background: #1e1e1e;
            }
            QTabBar::tab {
                background: #2d2d30;
                color: #d4d4d4;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: #1e1e1e;
                color: #007acc;
                border-bottom: 2px solid #007acc;
            }
            QTabBar::tab:hover {
                background: #3e3e42;
            }
            QPushButton {
                background: #0e639c;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background: #1177bb;
            }
            QPushButton:pressed {
                background: #007acc;
            }
            QLineEdit {
                background: #3c3c3c;
                color: #d4d4d4;
                border: 1px solid #555;
                padding: 4px 8px;
                border-radius: 3px;
            }
            QLineEdit:focus {
                border: 1px solid #007acc;
            }
            QTextEdit {
                background: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
                font-family: 'Courier New', monospace;
            }
        """)
        
    def load_results(self):
        """Load all result files from the results directory"""
        if not self.results_dir.exists():
            QMessageBox.warning(
                self, 
                "Directory Not Found",
                f"Results directory '{self.results_dir}' not found!\n\n"
                "Make sure you've run the analysis script first."
            )
            return
        
        txt_files = sorted(self.results_dir.glob("*.txt"))
        
        if not txt_files:
            QMessageBox.information(
                self,
                "No Results",
                f"No .txt files found in '{self.results_dir}'/\n\n"
                "Run the analysis script first to generate results."
            )
            return
        
        for file_path in txt_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                name = file_path.stem
                self.results[name] = content
                self.original_contents[name] = content
                
                # Create tab with text widget
                text_edit = QTextEdit()
                text_edit.setReadOnly(True)
                text_edit.setPlainText(content)
                text_edit.setFont(QFont("Courier New", 10))
                text_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
                
                # Store reference
                self.text_widgets[name] = text_edit
                
                # Add tab with nice name
                display_name = name.replace('_', ' ').title()
                self.tabs.addTab(text_edit, display_name)
                
            except Exception as e:
                print(f"[!] Error loading {file_path}: {e}")
        
        self.statusBar().showMessage(f"Loaded {len(self.results)} result files")
        
    def copy_current_tab(self):
        """Copy current tab content to clipboard"""
        current_widget = self.tabs.currentWidget()
        if current_widget and isinstance(current_widget, QTextEdit):
            text = current_widget.toPlainText()
            QApplication.clipboard().setText(text)
            self.statusBar().showMessage("✓ Copied to clipboard!", 3000)
        
    def filter_current_tab(self, search_text):
        """Filter current tab content based on search text"""
        current_idx = self.tabs.currentIndex()
        if current_idx < 0:
            return
        
        # Get the tab name from our results dict
        tab_names = list(self.results.keys())
        if current_idx >= len(tab_names):
            return
            
        tab_name = tab_names[current_idx]
        text_widget = self.text_widgets.get(tab_name)
        
        if not text_widget or not search_text:
            # Restore original if search is empty
            if text_widget and not search_text:
                text_widget.setPlainText(self.original_contents[tab_name])
            return
        
        # Filter lines containing search text (case-insensitive)
        original = self.original_contents[tab_name]
        lines = original.split('\n')
        filtered_lines = [line for line in lines if search_text.lower() in line.lower()]
        
        filtered_text = '\n'.join(filtered_lines)
        text_widget.setPlainText(filtered_text)
        
        # Update status
        match_count = len(filtered_lines)
        self.statusBar().showMessage(f"Found {match_count} matching lines")
        
    def clear_filter(self):
        """Clear search box and restore original content"""
        self.search_box.clear()
        current_idx = self.tabs.currentIndex()
        if current_idx >= 0:
            tab_names = list(self.results.keys())
            if current_idx < len(tab_names):
                tab_name = tab_names[current_idx]
                text_widget = self.text_widgets.get(tab_name)
                if text_widget:
                    text_widget.setPlainText(self.original_contents[tab_name])
        self.statusBar().showMessage("Filter cleared")
        
    def on_tab_changed(self, index):
        """Handle tab change - reapply filter if active"""
        search_text = self.search_box.text()
        if search_text:
            self.filter_current_tab(search_text)
        
    def open_results_dir(self):
        """Open results directory in file manager"""
        import subprocess
        import platform
        
        path = str(self.results_dir.absolute())
        
        try:
            if platform.system() == "Windows":
                subprocess.run(["explorer", path])
            elif platform.system() == "Darwin":  # macOS
                subprocess.run(["open", path])
            else:  # Linux
                subprocess.run(["xdg-open", path])
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Could not open directory:\n{e}")


def main():
    app = QApplication(sys.argv)
    
    # Get results directory from command line or use default
    results_dir = sys.argv[1] if len(sys.argv) > 1 else "results"
    
    viewer = ResultViewer(results_dir)
    viewer.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()