import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QMessageBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QDialog
)
from PyQt5.QtCore import Qt

from config_db import ConfigDB
from credential_manager import CredentialManager


class LoginWindow(QDialog):

    def __init__(self, db_config: ConfigDB, parent=None):
        super().__init__(parent)
        self.db_config = db_config
        self.setWindowTitle("Access Manager")
        self.setGeometry(300, 300, 400, 250)

        self.encryption_key = None

        self.is_initialized = self.db_config.is_initialized()

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout()

        if self.is_initialized:
            title_text = "Login with Master Password"
            button_text = "Login"
            self.confirm_mp_entry = None
        else:
            title_text = "Set New Master Password"
            button_text = "Initialize & Login"

        layout.addWidget(
            QLabel(f"<b>{title_text}</b>", alignment=Qt.AlignCenter))

        layout.addWidget(QLabel("Master Password:"))
        self.mp_entry = QLineEdit()
        self.mp_entry.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.mp_entry)

        if not self.is_initialized:
            layout.addWidget(QLabel("Confirm Password:"))
            self.confirm_mp_entry = QLineEdit()
            self.confirm_mp_entry.setEchoMode(QLineEdit.Password)
            layout.addWidget(self.confirm_mp_entry)

        login_button = QPushButton(button_text)
        login_button.clicked.connect(self._handle_action)
        layout.addWidget(login_button)

        self.setLayout(layout)

    def _handle_action(self):
        mp = self.mp_entry.text()

        if not mp:
            QMessageBox.warning(
                self, "Warning", "Master Password cannot be empty.")
            return

        if self.is_initialized:

            key = self.db_config.verify_master_password(mp)
            if key:
                self.encryption_key = key
                self.accept()
            else:
                QMessageBox.critical(
                    self, "Error", "Incorrect Master Password.")
                self.mp_entry.clear()
        else:

            confirm_mp = self.confirm_mp_entry.text()
            if mp != confirm_mp:
                QMessageBox.warning(self, "Warning", "Passwords do not match.")
                return

            try:
                self.db_config.initialize_master_password(mp)
                QMessageBox.information(
                    self, "Success", "Master Password set successfully!")

                self.encryption_key = self.db_config.verify_master_password(mp)
                if self.encryption_key:
                    self.accept()
                else:
                    QMessageBox.critical(
                        self, "Error", "Initialization failed to generate key.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Database error: {e}")


class MainWindow(QMainWindow):

    def __init__(self, encryption_key: bytes):
        super().__init__()
        self.setWindowTitle("Secure Python Password Manager (PyQt5)")
        self.setGeometry(100, 100, 800, 500)

        self.manager = CredentialManager(encryption_key)

        self._setup_ui()
        self._load_credentials()

    def _setup_ui(self):

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)

        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel("<h1>Stored Credentials</h1>"))

        self.add_button = QPushButton("Add New Credential")
        self.add_button.clicked.connect(self._add_credential_dialog)
        header_layout.addWidget(self.add_button)

        self.edit_button = QPushButton("Edit Selected")
        self.edit_button.clicked.connect(self._edit_selected_credential)
        header_layout.addWidget(self.edit_button)

        self.delete_button = QPushButton("Delete Selected")
        self.delete_button.clicked.connect(self._delete_selected_credential)
        header_layout.addWidget(self.delete_button)

        self.refresh_button = QPushButton("Refresh List")
        self.refresh_button.clicked.connect(self._load_credentials)
        header_layout.addWidget(self.refresh_button)

        main_layout.addLayout(header_layout)

        self.table = QTableWidget()
        self.table.setColumnCount(1)
        self.table.setHorizontalHeaderLabels(["Site Name"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        self.table.cellDoubleClicked.connect(self._retrieve_credential)

        main_layout.addWidget(self.table)

    def _load_credentials(self):

        sites = self.manager.list_sites()

        self.table.setRowCount(len(sites))
        for row, site in enumerate(sites):
            item = QTableWidgetItem(site)
            item.setFlags(item.flags() ^ Qt.ItemIsEditable)
            self.table.setItem(row, 0, item)

    def _add_credential_dialog(self):

        dialog = QDialog(self)
        dialog.setWindowTitle("Add New Credential")
        vbox = QVBoxLayout()

        fields = {"Site Name": QLineEdit(), "Username": QLineEdit(),
                  "Password": QLineEdit()}
        fields["Password"].setEchoMode(QLineEdit.Password)

        for name, entry in fields.items():
            vbox.addWidget(QLabel(name + ":"))
            vbox.addWidget(entry)

        save_button = QPushButton("Save Credential")

        def save_action():
            site = fields["Site Name"].text()
            user = fields["Username"].text()
            password = fields["Password"].text()

            if site and user and password:
                if self.manager.add_credential(site, user, password):
                    QMessageBox.information(
                        dialog, "Success", f"Credential for {site} added.")
                    self._load_credentials()
                    dialog.close()
                else:
                    QMessageBox.warning(
                        dialog, "Error", "Failed to add credential (Name may already exist).")
            else:
                QMessageBox.warning(dialog, "Warning",
                                    "All fields are required.")

        save_button.clicked.connect(save_action)
        vbox.addWidget(save_button)
        dialog.setLayout(vbox)
        dialog.exec_()

    def _retrieve_credential(self, row, column):

        if not self.table.selectionModel():
            return

        site_name = self.table.item(row, 0).text()
        credential = self.manager.get_credential(site_name)

        if credential:

            details = (
                f"Site: {credential['site_name']}\n"
                f"Username: {credential['username']}\n"
                f"Password: {credential['password']}"
            )
            QMessageBox.information(self, f"Details for {site_name}", details)
        else:
            QMessageBox.critical(self, "Retrieval Error",
                                 "Could not retrieve or decrypt the credential.")

    def _delete_selected_credential(self):

        selected_rows = self.table.selectionModel().selectedRows()

        if not selected_rows:
            QMessageBox.warning(self, "Selection Required",
                                "Please select a credential to delete.")
            return

        row = selected_rows[0].row()
        site_name = self.table.item(row, 0).text()

        reply = QMessageBox.question(self, 'Confirm Deletion',
                                     f"Are you sure you want to permanently delete the credential for '{site_name}'?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

        if reply == QMessageBox.Yes:
            if self.manager.delete_credential(site_name):
                QMessageBox.information(
                    self, "Success", f"Credential for '{site_name}' deleted.")
                self._load_credentials()
            else:
                QMessageBox.critical(
                    self, "Error", "Failed to delete the credential from the database.")

    def _edit_selected_credential(self):

        selected_rows = self.table.selectionModel().selectedRows()

        if not selected_rows:
            QMessageBox.warning(self, "Selection Required",
                                "Please select a credential to edit.")
            return

        row = selected_rows[0].row()
        site_name = self.table.item(row, 0).text()
        credential = self.manager.get_credential(site_name)

        if not credential:
            QMessageBox.critical(
                self, "Error", "Could not retrieve credential for editing.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Edit Credential: {site_name}")
        vbox = QVBoxLayout()

        fields = {"Site Name": QLineEdit(), "Username": QLineEdit(),
                  "Password": QLineEdit()}
        fields["Password"].setEchoMode(QLineEdit.Password)

        fields["Site Name"].setText(site_name)
        fields["Site Name"].setEnabled(False)
        fields["Username"].setText(credential['username'])
        fields["Password"].setText(credential['password'])

        for name, entry in fields.items():
            vbox.addWidget(QLabel(name + ":"))
            vbox.addWidget(entry)

        update_button = QPushButton("Update Credential")

        def update_action():
            new_user = fields["Username"].text()
            new_pass = fields["Password"].text()

            if new_user and new_pass:
                if self.manager.update_credential(site_name, new_user, new_pass):
                    QMessageBox.information(
                        dialog, "Success", f"Credential for {site_name} updated.")
                    self._load_credentials()
                    dialog.close()
                else:
                    QMessageBox.critical(
                        dialog, "Error", "Failed to update credential.")
            else:
                QMessageBox.warning(dialog, "Warning",
                                    "Username and Password are required.")

        update_button.clicked.connect(update_action)
        vbox.addWidget(update_button)
        dialog.setLayout(vbox)
        dialog.exec_()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    db_config = ConfigDB()

    login_dialog = LoginWindow(db_config)

    if login_dialog.exec_() == QDialog.Accepted:

        encryption_key = login_dialog.encryption_key
        main_window = MainWindow(encryption_key)
        main_window.show()

        sys.exit(app.exec_())
    else:

        sys.exit(0)
