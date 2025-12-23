import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QMessageBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QDialog, QFrame
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont

from config_db import ConfigDB
from credential_manager import CredentialManager

# --- MODERN UI STYLESHEET (QSS) ---
STYLESHEET = """
    QMainWindow, QDialog {
        background-color: #1e1e2e;
        color: #cdd6f4;
    }
    QLabel {
        color: #cdd6f4;
        font-size: 14px;
    }
    QLineEdit {
        background-color: #313244;
        color: #cdd6f4;
        border: 1px solid #45475a;
        border-radius: 6px;
        padding: 8px;
        font-size: 14px;
        selection-background-color: #89b4fa;
    }
    QLineEdit:focus {
        border: 1px solid #89b4fa;
    }
    QPushButton {
        background-color: #89b4fa;
        color: #11111b;
        border-radius: 6px;
        padding: 10px 20px;
        font-weight: bold;
        font-size: 13px;
    }
    QPushButton:hover {
        background-color: #b4befe;
    }
    QPushButton:pressed {
        background-color: #74c7ec;
    }
    QPushButton#delete_btn {
        background-color: #f38ba8;
    }
    QPushButton#delete_btn:hover {
        background-color: #eba0ac;
    }
    QTableWidget {
        background-color: #181825;
        alternate-background-color: #1e1e2e;
        color: #cdd6f4;
        gridline-color: #313244;
        border: 1px solid #313244;
        border-radius: 8px;
        font-size: 14px;
        selection-background-color: #45475a;
    }
    QHeaderView::section {
        background-color: #313244;
        color: #89b4fa;
        padding: 6px;
        border: none;
        font-weight: bold;
    }
"""


class LoginWindow(QDialog):
    def __init__(self, db_config: ConfigDB, parent=None):
        super().__init__(parent)
        self.db_config = db_config
        self.setWindowTitle("Secure Vault Login")
        self.setFixedSize(400, 300)
        self.encryption_key = None
        self.is_initialized = self.db_config.is_initialized()
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(15)

        title = "Access Manager" if self.is_initialized else "Initialize Vault"
        header = QLabel(f"<h2>{title}</h2>")
        header.setAlignment(Qt.AlignCenter)
        layout.addWidget(header)

        layout.addWidget(QLabel("Master Password"))
        self.mp_entry = QLineEdit()
        self.mp_entry.setPlaceholderText("Enter your master password...")
        self.mp_entry.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.mp_entry)

        if not self.is_initialized:
            layout.addWidget(QLabel("Confirm Password"))
            self.confirm_mp_entry = QLineEdit()
            self.confirm_mp_entry.setPlaceholderText(
                "Confirm your password...")
            self.confirm_mp_entry.setEchoMode(QLineEdit.Password)
            layout.addWidget(self.confirm_mp_entry)

        btn_text = "Login" if self.is_initialized else "Create Vault"
        login_button = QPushButton(btn_text)
        login_button.setCursor(Qt.PointingHandCursor)
        login_button.clicked.connect(self._handle_action)
        layout.addWidget(login_button)

        self.setLayout(layout)

    def _handle_action(self):
        mp = self.mp_entry.text()
        if not mp:
            QMessageBox.warning(self, "Empty Field",
                                "Please enter a password.")
            return

        if self.is_initialized:
            key = self.db_config.verify_master_password(mp)
            if key:
                self.encryption_key = key
                self.accept()
            else:
                QMessageBox.critical(self, "Access Denied",
                                     "Incorrect Master Password.")
                self.mp_entry.clear()
        else:
            confirm_mp = self.confirm_mp_entry.text()
            if mp != confirm_mp:
                QMessageBox.warning(
                    self, "Mismatch", "Passwords do not match.")
                return
            try:
                self.db_config.initialize_master_password(mp)
                QMessageBox.information(
                    self, "Initialized", "Vault created successfully!")
                self.encryption_key = self.db_config.verify_master_password(mp)
                if self.encryption_key:
                    self.accept()
            except Exception as e:
                QMessageBox.critical(self, "System Error",
                                     f"Database error: {e}")


class MainWindow(QMainWindow):
    def __init__(self, encryption_key: bytes):
        super().__init__()
        self.setWindowTitle("Secure Vault")
        self.resize(900, 600)
        self.manager = CredentialManager(encryption_key)
        self._setup_ui()
        self._load_credentials()

    def _setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)

        # Header Section
        header_layout = QHBoxLayout()
        title_label = QLabel("<h1>My Credentials</h1>")
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        # Action Buttons
        self.add_button = QPushButton("+ Add")
        self.add_button.clicked.connect(self._add_credential_dialog)

        self.edit_button = QPushButton("Edit")
        self.edit_button.clicked.connect(self._edit_selected_credential)

        self.delete_button = QPushButton("Delete")
        self.delete_button.setObjectName("delete_btn")  # Special color via QSS
        self.delete_button.clicked.connect(self._delete_selected_credential)

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self._load_credentials)

        for btn in [self.add_button, self.edit_button, self.delete_button, self.refresh_button]:
            btn.setCursor(Qt.PointingHandCursor)
            header_layout.addWidget(btn)

        main_layout.addLayout(header_layout)

        # Table Section
        self.table = QTableWidget()
        self.table.setColumnCount(1)
        self.table.setHorizontalHeaderLabels(["Site Name"])
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.cellDoubleClicked.connect(self._retrieve_credential)

        main_layout.addWidget(self.table)

    def _load_credentials(self):
        sites = self.manager.list_sites()
        self.table.setRowCount(len(sites))
        for row, site in enumerate(sites):
            item = QTableWidgetItem(site)
            item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, 0, item)

    def _add_credential_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("New Credential")
        dialog.setFixedWidth(350)
        vbox = QVBoxLayout(dialog)
        vbox.setContentsMargins(20, 20, 20, 20)
        vbox.setSpacing(10)

        fields = {}
        for label in ["Site Name", "Username", "Password"]:
            vbox.addWidget(QLabel(label))
            entry = QLineEdit()
            if label == "Password":
                entry.setEchoMode(QLineEdit.Password)
            vbox.addWidget(entry)
            fields[label] = entry

        save_btn = QPushButton("Save to Vault")

        def save_action():
            s, u, p = fields["Site Name"].text(
            ), fields["Username"].text(), fields["Password"].text()
            if s and u and p:
                if self.manager.add_credential(s, u, p):
                    self._load_credentials()
                    dialog.close()
                else:
                    QMessageBox.warning(
                        dialog, "Error", "Site name already exists.")
            else:
                QMessageBox.warning(dialog, "Required",
                                    "Please fill all fields.")

        save_btn.clicked.connect(save_action)
        vbox.addWidget(save_btn)
        dialog.exec_()

    def _retrieve_credential(self, row, column):
        site_name = self.table.item(row, 0).text()
        cred = self.manager.get_credential(site_name)
        if cred:
            msg = f"<b>Site:</b> {cred['site_name']}<br><b>User:</b> {cred['username']}<br><b>Pass:</b> {cred['password']}"
            QMessageBox.information(self, "Credential Details", msg)

    def _delete_selected_credential(self):
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.warning(self, "Selection", "Select a row to delete.")
            return

        site_name = self.table.item(selected[0].row(), 0).text()
        reply = QMessageBox.question(
            self, 'Confirm', f"Delete '{site_name}' permanently?", QMessageBox.Yes | QMessageBox.No)

        if reply == QMessageBox.Yes:
            if self.manager.delete_credential(site_name):
                self._load_credentials()

    def _edit_selected_credential(self):
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.warning(self, "Selection", "Select a row to edit.")
            return

        row = selected[0].row()
        site_name = self.table.item(row, 0).text()
        cred = self.manager.get_credential(site_name)

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Edit {site_name}")
        vbox = QVBoxLayout(dialog)
        vbox.setContentsMargins(20, 20, 20, 20)

        u_entry = QLineEdit(cred['username'])
        p_entry = QLineEdit(cred['password'])
        p_entry.setEchoMode(QLineEdit.Password)

        vbox.addWidget(QLabel("Username"))
        vbox.addWidget(u_entry)
        vbox.addWidget(QLabel("Password"))
        vbox.addWidget(p_entry)

        update_btn = QPushButton("Update")

        def update_action():
            if self.manager.update_credential(site_name, u_entry.text(), p_entry.text()):
                self._load_credentials()
                dialog.close()

        update_btn.clicked.connect(update_action)
        vbox.addWidget(update_btn)
        dialog.exec_()


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Apply Global Styles
    app.setStyleSheet(STYLESHEET)

    db_config = ConfigDB()
    login = LoginWindow(db_config)

    if login.exec_() == QDialog.Accepted:
        main = MainWindow(login.encryption_key)
        main.show()
        sys.exit(app.exec_())
    else:
        sys.exit(0)
