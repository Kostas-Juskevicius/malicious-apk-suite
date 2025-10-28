#!/usr/bin/env python3
import sys
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QTextEdit, 
    QVBoxLayout, QHBoxLayout, QWidget, QPushButton,
    QLineEdit, QLabel, QMessageBox
)
from PyQt6.QtGui import QFont, QColor, QPalette, QTextCursor, QShortcut, QKeySequence
from PyQt6.QtCore import Qt

class ResultViewer(QMainWindow):
    def __init__(self, results_dir="results"):
        super().__init__()
        self.results_dir = Path(results_dir)
        self.cheatsheet_file = Path("python/resources/permission_cheatsheet.txt")
        self.results = {}
        self.text_widgets = {}
        self.original_contents = {}
        self.cheatsheet_widget = None
        self.find_visible = False
        self.current_find_matches = []
        self.current_find_index = -1
        
        self.init_ui()
        self.load_results()
        self.load_cheatsheet()
        self.setup_shortcuts()
        
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
        
        # Filter box
        filter_label = QLabel("Filter:")
        self.filter_box = QLineEdit()
        self.filter_box.setPlaceholderText("Filter lines...")
        
        # Filter button
        filter_btn = QPushButton("Apply Filter")
        filter_btn.clicked.connect(self.apply_filter)
        
        clear_filter_btn = QPushButton("Clear Filter")
        clear_filter_btn.clicked.connect(self.clear_filter)
        
        # Copy button
        copy_btn = QPushButton("Copy Tab")
        copy_btn.clicked.connect(self.copy_current_tab)
        
        top_bar.addWidget(filter_label)
        top_bar.addWidget(self.filter_box, stretch=1)
        top_bar.addWidget(filter_btn)
        top_bar.addWidget(clear_filter_btn)
        top_bar.addWidget(copy_btn)
        
        layout.addLayout(top_bar)
        
        # Find bar (hidden by default)
        self.find_bar = QWidget()
        find_layout = QHBoxLayout(self.find_bar)
        find_layout.setContentsMargins(0, 0, 0, 0)
        
        find_label = QLabel("Find:")
        self.find_box = QLineEdit()
        self.find_box.setPlaceholderText("Search in current tab...")
        self.find_box.returnPressed.connect(self.find_next)
        
        self.find_prev_btn = QPushButton("◄ Previous")
        self.find_prev_btn.clicked.connect(self.find_previous)
        
        self.find_next_btn = QPushButton("Next ►")
        self.find_next_btn.clicked.connect(self.find_next)
        
        self.find_status = QLabel("")
        
        close_find_btn = QPushButton("✕")
        close_find_btn.setMaximumWidth(30)
        close_find_btn.clicked.connect(self.hide_find_bar)
        
        find_layout.addWidget(find_label)
        find_layout.addWidget(self.find_box, stretch=1)
        find_layout.addWidget(self.find_prev_btn)
        find_layout.addWidget(self.find_next_btn)
        find_layout.addWidget(self.find_status)
        find_layout.addWidget(close_find_btn)
        
        self.find_bar.setVisible(False)
        layout.addWidget(self.find_bar)
        
        # Tab widget
        self.tabs = QTabWidget()
        self.tabs.currentChanged.connect(self.on_tab_changed)
        layout.addWidget(self.tabs)
        
        # Status bar
        self.statusBar().showMessage("Ready")
        
    def setup_shortcuts(self):
        """Setup keyboard shortcuts"""
        # Ctrl+F for find
        find_shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
        find_shortcut.activated.connect(self.show_find_bar)
        
        # Escape to close find bar
        escape_shortcut = QShortcut(QKeySequence("Escape"), self)
        escape_shortcut.activated.connect(self.hide_find_bar)
        
        # F3 for find next
        f3_shortcut = QShortcut(QKeySequence("F3"), self)
        f3_shortcut.activated.connect(self.find_next)
        
        # Shift+F3 for find previous
        shift_f3_shortcut = QShortcut(QKeySequence("Shift+F3"), self)
        shift_f3_shortcut.activated.connect(self.find_previous)
        
    def show_find_bar(self):
        """Show the find bar and focus the search box"""
        self.find_bar.setVisible(True)
        self.find_box.setFocus()
        self.find_box.selectAll()
        
    def hide_find_bar(self):
        """Hide the find bar and clear highlights"""
        self.find_bar.setVisible(False)
        self.clear_find_highlights()
        self.current_find_matches = []
        self.current_find_index = -1
        self.find_status.setText("")
        
    def clear_find_highlights(self):
        """Clear all find highlights in current tab"""
        current_widget = self.tabs.currentWidget()
        if current_widget and isinstance(current_widget, QTextEdit):
            cursor = current_widget.textCursor()
            cursor.clearSelection()
            current_widget.setTextCursor(cursor)
            
    def find_next(self):
        """Find next occurrence of search text"""
        search_text = self.find_box.text()
        if not search_text:
            return
            
        current_widget = self.tabs.currentWidget()
        if not current_widget or not isinstance(current_widget, QTextEdit):
            return
        
        # Search from current cursor position
        flags = QTextCursor.FindFlag(0)  # Default search
        found = current_widget.find(search_text, flags)
        
        if not found:
            # Wrap around to beginning
            cursor = current_widget.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            current_widget.setTextCursor(cursor)
            found = current_widget.find(search_text, flags)
            
            if found:
                self.find_status.setText("(wrapped)")
            else:
                self.find_status.setText("Not found")
        else:
            self.find_status.setText("")
            
    def find_previous(self):
        """Find previous occurrence of search text"""
        search_text = self.find_box.text()
        if not search_text:
            return
            
        current_widget = self.tabs.currentWidget()
        if not current_widget or not isinstance(current_widget, QTextEdit):
            return
        
        # Search backwards
        flags = QTextCursor.FindFlag.FindBackward
        found = current_widget.find(search_text, flags)
        
        if not found:
            # Wrap around to end
            cursor = current_widget.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            current_widget.setTextCursor(cursor)
            found = current_widget.find(search_text, flags)
            
            if found:
                self.find_status.setText("(wrapped)")
            else:
                self.find_status.setText("Not found")
        else:
            self.find_status.setText("")
        
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
        
    def load_cheatsheet(self):
        """Load permission cheatsheet as a separate tab"""
        if not self.cheatsheet_file.exists():
            print(f"[*] Cheatsheet file not found: {self.cheatsheet_file}")
            return
        
        try:
            with open(self.cheatsheet_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Create text widget for cheatsheet
            text_edit = QTextEdit()
            text_edit.setReadOnly(True)
            text_edit.setPlainText(content)
            text_edit.setFont(QFont("Courier New", 10))
            text_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
            
            # Store reference
            self.cheatsheet_widget = text_edit
            self.text_widgets['cheatsheet'] = text_edit
            self.original_contents['cheatsheet'] = content
            self.results['cheatsheet'] = content
            
            # Add as first tab with a special icon/name
            self.tabs.insertTab(0, text_edit, "📋 Permission Cheatsheet")
            
            print(f"[*] Loaded cheatsheet from {self.cheatsheet_file}")
            
        except Exception as e:
            print(f"[*] Error loading cheatsheet: {e}")

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
    
    def apply_filter(self):
        """Apply line filter to current tab"""
        search_text = self.filter_box.text()
        current_idx = self.tabs.currentIndex()
        if current_idx < 0 or not search_text:
            return
        
        # Get the tab name from our results dict
        tab_names = list(self.results.keys())
        if current_idx >= len(tab_names):
            return
            
        tab_name = tab_names[current_idx]
        text_widget = self.text_widgets.get(tab_name)
        
        if not text_widget:
            return
        
        # Filter lines containing search text (case-insensitive)
        original = self.original_contents[tab_name]
        lines = original.split('\n')
        filtered_lines = [line for line in lines if search_text.lower() in line.lower()]
        
        filtered_text = '\n'.join(filtered_lines)
        text_widget.setPlainText(filtered_text)
        
        # Update status
        match_count = len(filtered_lines)
        self.statusBar().showMessage(f"Filter applied: {match_count} matching lines")
        
    def clear_filter(self):
        """Clear filter and restore original content"""
        self.filter_box.clear()
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
        """Handle tab change"""
        # Clear find when switching tabs
        if self.find_bar.isVisible():
            self.clear_find_highlights()


def main():
    app = QApplication(sys.argv)
    
    # Get results directory from command line or use default
    results_dir = sys.argv[1] if len(sys.argv) > 1 else "results"
    
    viewer = ResultViewer(results_dir)
    viewer.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()