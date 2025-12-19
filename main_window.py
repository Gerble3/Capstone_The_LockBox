# main_window.py (PyQt6)

# CSCI 490 Capstone Project 
# By Reed Clayton

# Info on Running the code available in README.md

# Various Used Sources: (Too lazy to add more formal citations)
# Cloud Vault project by Schimizu (modified)
# https://python.plainenglish.io/i-built-a-local-password-vault-in-python-that-encrypts-and-stores-logins-securely-ff339dd46a01 
# References for cryptography and password storage:
# https://schimizu.com/understanding-salt-bcrypt-argon2id-ncrypt-and-pepper-essential-concepts-for-secure-password-df160ab062bf 
# stackoverflow on argon2id usage in python
# https://stackoverflow.com/questions/58431973/argon2-library-that-hashes-passwords-without-a-secret-and-with-a-random-salt-tha 
# Cryptography docs for AES-GCM
# https://pycryptodome.readthedocs.io/en/latest/src/introduction.html 
# References for CSV import and parsing:
# https://stackoverflow.com/questions/12042724/securely-storing-passwords-for-use-in-python-script 
# References for PyQt6 UI elements and patterns:
# https://www.geeksforgeeks.org/python/working-csv-files-python/ 
# TutorialsPoint PyQt6 documentation
# https://coderslegacy.com/creating-a-login-form-with-pyqt6/ 
# PyQt6 official documentation
# https://www.riverbankcomputing.com/static/Docs/PyQt6/ 


from __future__ import annotations
import sys, time, os, shutil
from typing import Optional
import secrets, string

from cloud_vault.importer import import_csv, preview_csv, FORMATS
from PyQt6 import QtCore, QtGui, QtWidgets

# Backend
from cloud_vault.db import (
    add_entry, update_entry, delete_entry, list_entries, get_entry, Vault
)

# Table Model for entries (I color coded in a Password column)
class EntryTableModel(QtCore.QAbstractTableModel):
    # Add a Password column
    COLS = ["Title", "URL", "Username", "Password", "Host", "Updated"]

    def __init__(self, vault: Vault):
        super().__init__()
        self.vault = vault
        self._rows = []  # list of dicts from list_entries()
        self.refresh()

    def refresh(self):
        self.beginResetModel()
        # ask backend to include decrypted passwords
        self._rows = list_entries(self.vault, reveal_password=True)
        self.endResetModel()

    def rowCount(self, parent=QtCore.QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QtCore.QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.COLS)


    def data(self, index: QtCore.QModelIndex, role=QtCore.Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or not (0 <= index.row() < len(self._rows)):
            return None
        r = self._rows[index.row()]
        col = index.column()
        # Provide data for display and editing 
        if role in (QtCore.Qt.ItemDataRole.DisplayRole, QtCore.Qt.ItemDataRole.EditRole):
            if col == 0: return r["title"]
            if col == 1: return r["url"]
            if col == 2: return r["username"]
            if col == 3: return r.get("password", "")  # new column
            if col == 4: return r["host"]
            if col == 5:
                return time.strftime("%Y-%m-%d %H:%M", time.localtime(r["updated_at"]))
        return None

    def headerData(self, section, orientation, role=QtCore.Qt.ItemDataRole.DisplayRole):
        if role != QtCore.Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == QtCore.Qt.Orientation.Horizontal and 0 <= section < len(self.COLS):
            return self.COLS[section]
        return None

    def entry_id_at(self, row: int) -> Optional[int]:
        if 0 <= row < len(self._rows):
            return self._rows[row]["id"]
        return None


# Add/Edit Dialog (with password generator)
class EntryDialog(QtWidgets.QDialog):
    def __init__(self, parent=None, title="Add Entry", data=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)

        # Inputs 
        self.e_title = QtWidgets.QLineEdit()
        self.e_url = QtWidgets.QLineEdit()
        self.e_username = QtWidgets.QLineEdit()
        self.e_password = QtWidgets.QLineEdit()
        self.e_password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.chk_show = QtWidgets.QCheckBox("Show")
        self.e_notes = QtWidgets.QPlainTextEdit()
        self.e_notes.setMinimumHeight(80)

        # Password generator controls 
        self.spin_len = QtWidgets.QSpinBox()
        self.spin_len.setRange(8, 64)
        self.spin_len.setValue(16)
        self.chk_symbols = QtWidgets.QCheckBox("Symbols")
        self.chk_symbols.setChecked(True)
        self.btn_gen = QtWidgets.QPushButton("Generate")
        self.btn_copy = QtWidgets.QPushButton("Copy")
        self.gen_status = QtWidgets.QLabel("")
        self.gen_status.setStyleSheet("color:#888")

        # Show/Hide password
        self.chk_show.toggled.connect(
            lambda on: self.e_password.setEchoMode(
                QtWidgets.QLineEdit.EchoMode.Normal if on else QtWidgets.QLineEdit.EchoMode.Password
            )
        )

        # Layout 
        form = QtWidgets.QFormLayout()
        form.addRow("Title*", self.e_title)
        form.addRow("URL", self.e_url)
        form.addRow("Username", self.e_username)

        # Password row with eye toggle
        pw_row = QtWidgets.QHBoxLayout()
        pw_row.addWidget(self.e_password, 1)
        pw_row.addWidget(self.chk_show)
        form.addRow("Password", pw_row)

        # Generator row
        gen_row = QtWidgets.QHBoxLayout()
        gen_row.addWidget(QtWidgets.QLabel("Length:"))
        gen_row.addWidget(self.spin_len)
        gen_row.addWidget(self.chk_symbols)
        gen_row.addStretch(1)
        gen_row.addWidget(self.btn_gen)
        gen_row.addWidget(self.btn_copy)
        form.addRow("", QtWidgets.QWidget())   # spacer line feel
        form.addRow("Generator", QtWidgets.QWidget())
        form.addRow("", self._wrap_layout(gen_row))
        form.addRow("", self.gen_status)

        form.addRow("Notes", self.e_notes)

        # Buttons
        btns = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)

        # Outer layout
        outer = QtWidgets.QVBoxLayout(self)
        outer.addLayout(form)
        outer.addWidget(btns)

        # Prefill for Edit
        if data:
            self.e_title.setText(data.get("title", ""))
            self.e_url.setText(data.get("url", ""))
            self.e_username.setText(data.get("username", ""))
            if data.get("password") is not None:
                self.e_password.setText(data["password"])
            self.e_notes.setPlainText(data.get("notes", ""))

        # Signals for generator
        self.btn_gen.clicked.connect(self._do_generate)
        self.btn_copy.clicked.connect(self._copy_password)

    # utility to place an HBox in a Form row
    def _wrap_layout(self, layout: QtWidgets.QHBoxLayout) -> QtWidgets.QWidget:
        w = QtWidgets.QWidget()
        w.setLayout(layout)
        return w

    # Generate password 
    def _do_generate(self):
        length = int(self.spin_len.value())
        use_symbols = self.chk_symbols.isChecked()

        # Build allowed characters securely
        chars = string.ascii_letters + string.digits
        if use_symbols:
            # a conservative symbol set that rarely conflicts with site rules
            chars += "!@#$%^&*()-_=+[]{}:,./?"

        # Ensure we include at least one of each required class (optional but nice)
        required_sets = [
            string.ascii_lowercase,
            string.ascii_uppercase,
            string.digits
        ]
        if use_symbols:
            required_sets.append("!@#$%^&*()-_=+[]{}:,./?")

        # Start with one from each required set (up to length)
        pwd_chars = []
        for s in required_sets:
            if len(pwd_chars) < length:
                pwd_chars.append(secrets.choice(s))

        # Fill the rest randomly
        while len(pwd_chars) < length:
            pwd_chars.append(secrets.choice(chars))

        # Shuffle to avoid a predictable order of required chars
        for i in range(len(pwd_chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            pwd_chars[i], pwd_chars[j] = pwd_chars[j], pwd_chars[i]

        pwd = "".join(pwd_chars)
        self.e_password.setText(pwd)
        self.e_password.selectAll()
        self.gen_status.setText(f"Generated {length}-char password.")

    #  Copy/auto clear clipboard 
    def _copy_password(self):
        pwd = self.e_password.text()
        if not pwd:
            self.gen_status.setText("Nothing to copy.")
            return
        cb = QtWidgets.QApplication.clipboard()
        cb.setText(pwd)
        self.gen_status.setText("Copied to clipboard (auto-clears in 15s).")
        QtCore.QTimer.singleShot(15000, lambda: self._clear_clipboard(cb))

    def _clear_clipboard(self, cb):
        # Avoid clearing something else the user might have copied since
        if cb.text() == self.e_password.text():
            cb.clear()
            self.gen_status.setText("Clipboard cleared.")

    # Collect field values 
    def values(self):
        title = self.e_title.text().strip()
        if not title:
            QtWidgets.QMessageBox.warning(self, "Missing", "Title is required.")
            return None
        return {
            "title": title,
            "url": self.e_url.text().strip(),
            "username": self.e_username.text(),
            "password": self.e_password.text(),
            "notes": self.e_notes.toPlainText(),
        }


# CSV Dialog 
class ImportCsvDialog(QtWidgets.QDialog):
    def __init__(self, parent=None, csv_path: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Import from CSV")
        self.setModal(True)
        self.csv_path = csv_path

        self.path_edit = QtWidgets.QLineEdit(csv_path)
        self.btn_browse = QtWidgets.QPushButton("Browse…")
        self.format_combo = QtWidgets.QComboBox()
        self.format_combo.addItems(FORMATS)  # auto, chrome, bitwarden, lastpass, generic
        self.chk_skip_empty = QtWidgets.QCheckBox("Skip entries with empty password")
        self.chk_skip_empty.setChecked(True)
        self.chk_dedupe = QtWidgets.QCheckBox("Skip duplicates by (host + username)")
        self.chk_dedupe.setChecked(True)

        # preview table
        self.preview = QtWidgets.QTableWidget(0, 0)
        self.preview.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.preview.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.NoSelection)
        self.preview.setMinimumHeight(220)

        # layout
        form = QtWidgets.QFormLayout()
        path_row = QtWidgets.QHBoxLayout()
        path_row.addWidget(self.path_edit, 1)
        path_row.addWidget(self.btn_browse)
        form.addRow("CSV File", self._wrap_row(path_row))
        form.addRow("Format", self.format_combo)
        form.addRow(self.chk_skip_empty)
        form.addRow(self.chk_dedupe)
        form.addRow("Preview (first rows)", self.preview)

        btns = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok |
            QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)

        outer = QtWidgets.QVBoxLayout(self)
        outer.addLayout(form)
        outer.addWidget(btns)

        # signals
        self.btn_browse.clicked.connect(self._browse)
        self.path_edit.textChanged.connect(self._refresh_preview)

        # initial load
        self._refresh_preview()

    def _wrap_row(self, layout: QtWidgets.QLayout) -> QtWidgets.QWidget:
        w = QtWidgets.QWidget()
        w.setLayout(layout)
        return w

    def _browse(self):
        dlg = QtWidgets.QFileDialog(self, "Select CSV to import", self.path_edit.text())
        dlg.setNameFilter("CSV files (*.csv);;All Files (*)")
        dlg.setAcceptMode(QtWidgets.QFileDialog.AcceptMode.AcceptOpen)
        if dlg.exec():
            self.path_edit.setText(dlg.selectedFiles()[0])

    def _refresh_preview(self):
        path = self.path_edit.text().strip()
        if not path or not os.path.exists(path):
            self.preview.clear()
            self.preview.setRowCount(0)
            self.preview.setColumnCount(0)
            return
        try:
            detected, headers, rows = preview_csv(path, limit=12)
            idx = self.format_combo.findText(detected)
            if idx >= 0:
                self.format_combo.setCurrentIndex(idx)

            self.preview.setColumnCount(len(headers))
            self.preview.setHorizontalHeaderLabels(headers)
            self.preview.setRowCount(len(rows))
            for r_i, r in enumerate(rows):
                for c_i, h in enumerate(headers):
                    item = QtWidgets.QTableWidgetItem(r.get(h, ""))
                    self.preview.setItem(r_i, c_i, item)
            self.preview.resizeColumnsToContents()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "Preview error", str(e))

    def values(self):
        return {
            "path": self.path_edit.text().strip(),
            "format": self.format_combo.currentText(),
            "skip_empty": self.chk_skip_empty.isChecked(),
            "dedupe": self.chk_dedupe.isChecked(),
        }


# Main Window 
class VaultMainWindow(QtWidgets.QMainWindow):
    def __init__(self, vault: Vault, db_path: str, autoclipper_seconds: int = 15, on_lock=None):
        super().__init__()
        self.vault = vault
        self.db_path = db_path
        self.autoclipper_seconds = autoclipper_seconds
        self.on_lock_cb = on_lock

        self.setWindowTitle("Lock Box — Vault")
        self.resize(900, 540)

        # Model + filter
        self.model = EntryTableModel(self.vault)
        self.proxy = QtCore.QSortFilterProxyModel(self)
        self.proxy.setFilterCaseSensitivity(QtCore.Qt.CaseSensitivity.CaseInsensitive)
        self.proxy.setFilterKeyColumn(-1)  # search all columns
        self.proxy.setSourceModel(self.model)

        # Table view
        self.table = QtWidgets.QTableView()
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)

        # Search box
        self.search = QtWidgets.QLineEdit()
        self.search.setPlaceholderText("Search title, url, username, host…")
        self.search.textChanged.connect(self.proxy.setFilterFixedString)

        # Toolbar actions 
        act_add = QtGui.QAction("Add", self)
        act_edit = QtGui.QAction("Edit", self)
        act_del = QtGui.QAction("Delete", self)
        act_copy = QtGui.QAction("Copy Password", self)
        act_refresh = QtGui.QAction("Refresh", self)
        act_lock = QtGui.QAction("Lock", self)

        act_add.triggered.connect(self.on_add)
        act_edit.triggered.connect(self.on_edit)
        act_del.triggered.connect(self.on_delete)
        act_copy.triggered.connect(self.on_copy_password)
        act_refresh.triggered.connect(self.on_refresh)
        act_lock.triggered.connect(self.on_lock)

        tb = self.addToolBar("Main")
        tb.addAction(act_add)
        tb.addAction(act_edit)
        tb.addAction(act_del)
        tb.addSeparator()
        tb.addAction(act_copy)
        tb.addSeparator()
        tb.addAction(act_refresh)
        tb.addSeparator()
        tb.addAction(act_lock)

        # Menu bar/File menu
        file_menu = self.menuBar().addMenu("&File")

        act_import = file_menu.addAction("Import from CSV…")
        act_import.triggered.connect(self.on_import_csv)

        act_cloud = file_menu.addAction("Set Cloud Sync Folder…")
        act_cloud.triggered.connect(self.on_set_cloud_folder)

        # Central layout
        central = QtWidgets.QWidget()
        lay = QtWidgets.QVBoxLayout(central)
        lay.addWidget(self.search)
        lay.addWidget(self.table, 1)
        self.setCentralWidget(central)

        # Status bar
        self.statusBar().showMessage(f"Opened: {self.db_path}")

        # Keyboard shortcuts
        act_add.setShortcut(QtGui.QKeySequence.StandardKey.New)
        act_copy.setShortcut(QtGui.QKeySequence("Ctrl+Shift+C"))

    #  helpers 
    def lock_and_return(self):
        # Just close; closeEvent handles DB + callback
        self.close()

    def _selected_entry_id(self) -> Optional[int]:
        sel = self.table.selectionModel().selectedRows()
        if not sel:
            return None
        proxy_row = sel[0].row()
        src_row = self.proxy.mapToSource(self.proxy.index(proxy_row, 0)).row()
        return self.model.entry_id_at(src_row)

    def _confirm(self, title: str, text: str) -> bool:
        resp = QtWidgets.QMessageBox.question(
            self, title, text,
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No
        )
        return resp == QtWidgets.QMessageBox.StandardButton.Yes

    #  Cloud Sync (file-based) 
    def on_set_cloud_folder(self):
        folder = QtWidgets.QFileDialog.getExistingDirectory(
            self, "Select a sync folder (Dropbox/Google Drive/Syncthing/etc.)"
        )
        if not folder:
            return

        def norm(p: str) -> str:
            return os.path.normcase(os.path.normpath(os.path.abspath(p)))

        chosen = norm(folder)

        # If the user already selected a folder named "LockBox" don't create LockBox/LockBox
        base_name = os.path.basename(chosen.rstrip("\\/"))
        if base_name.lower() == "lockbox":
            lockbox_dir = chosen
        else:
            lockbox_dir = norm(os.path.join(folder, "LockBox"))

        os.makedirs(lockbox_dir, exist_ok=True)

        current_db = norm(self.db_path)
        dest_db = norm(os.path.join(lockbox_dir, os.path.basename(self.db_path)))

        # If we're already using a DB inside that LockBox folder (same exact file), do nothing.
        if current_db == dest_db:
            QtWidgets.QMessageBox.information(
                self,
                "Cloud Sync",
                "This vault is already located in the selected LockBox sync folder.\n\n"
                f"{self.db_path}"
            )
            return

        # Best effort flush + close before copying
        try:
            self.vault.conn.commit()
        except Exception:
            pass
        try:
            self.vault.conn.close()
        except Exception:
            pass

        try:
            shutil.copy2(self.db_path, dest_db)
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Copy failed", str(e))
            return

        QtWidgets.QMessageBox.information(
            self,
            "Cloud Sync Enabled",
            "Vault copied to:\n\n"
            f"{dest_db}\n\n"
            "Next step:\n"
            "- Re-open Lock Box and select that vault.db path.\n"
            "Tip: avoid opening the same vault on two devices at the same time."
        )
        self.close()

    #  CSV Import 
    def on_import_csv(self):
        dlg = ImportCsvDialog(self)
        if not dlg.exec():
            return
        opts = dlg.values()
        path = opts["path"]
        if not path or not os.path.exists(path):
            QtWidgets.QMessageBox.warning(self, "Missing file", "Please select a valid CSV file.")
            return

        warn = QtWidgets.QMessageBox.question(
            self, "Security",
            "CSV exports are plaintext. Continue import and remember to delete the CSV after?",
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No
        )
        if warn != QtWidgets.QMessageBox.StandardButton.Yes:
            return

        stats = import_csv(
            self.vault,
            csv_path=path,
            fmt=opts["format"],
            skip_empty_passwords=opts["skip_empty"],
            dedupe=opts["dedupe"],
        )
        self.model.refresh()
        msg = (
            f"Imported: {stats['imported']}\n"
            f"Skipped (empty pw): {stats['skipped_empty']}\n"
            f"Skipped (duplicates): {stats['skipped_dupe']}\n"
            f"Errors: {stats['errors']}"
        )
        QtWidgets.QMessageBox.information(self, "Import complete", msg)

    # actions 
    def on_add(self):
        dlg = EntryDialog(self, "Add Entry")
        if dlg.exec():
            vals = dlg.values()
            if not vals:
                return
            add_entry(self.vault, **vals)
            self.model.refresh()
            self.statusBar().showMessage("Entry added.", 3000)

    def on_edit(self):
        eid = self._selected_entry_id()
        if eid is None:
            QtWidgets.QMessageBox.information(self, "Select", "Select a row to edit.")
            return
        cur = get_entry(self.vault, eid, reveal_password=True)
        dlg = EntryDialog(self, "Edit Entry", data=cur)
        if dlg.exec():
            vals = dlg.values()
            if not vals:
                return
            updates = {k: v for k, v in vals.items() if v != ""}
            update_entry(self.vault, eid, **updates)
            self.model.refresh()
            self.statusBar().showMessage("Entry updated.", 3000)

    def on_delete(self):
        eid = self._selected_entry_id()
        if eid is None:
            QtWidgets.QMessageBox.information(self, "Select", "Select a row to delete.")
            return
        if self._confirm("Delete", "Delete the selected entry? This cannot be undone."):
            delete_entry(self.vault, eid)
            self.model.refresh()
            self.statusBar().showMessage("Entry deleted.", 3000)

    def on_copy_password(self):
        eid = self._selected_entry_id()
        if eid is None:
            QtWidgets.QMessageBox.information(self, "Select", "Select a row to copy its password.")
            return
        try:
            e = get_entry(self.vault, eid, reveal_password=True)
            pw = e.get("password") or ""
            if not pw:
                QtWidgets.QMessageBox.information(self, "Empty", "This entry has no password.")
                return
            cb = QtWidgets.QApplication.clipboard()
            cb.setText(pw)
            self.statusBar().showMessage(f"Password copied. Auto-clearing in {self.autoclipper_seconds}s…")

            QtCore.QTimer.singleShot(
                self.autoclipper_seconds * 1000,
                lambda: self._clear_clipboard_if_match(pw)
            )
        except Exception as ex:
            QtWidgets.QMessageBox.critical(self, "Error", str(ex))

    def _clear_clipboard_if_match(self, pw: str):
        cb = QtWidgets.QApplication.clipboard()
        if cb.text() == pw:
            cb.clear()
            self.statusBar().showMessage("Clipboard cleared.", 3000)

    def on_refresh(self):
        self.model.refresh()
        self.statusBar().showMessage("Refreshed.", 2000)

    def on_lock(self):
        self.lock_and_return()

    def closeEvent(self, event: QtGui.QCloseEvent):
        # If user closes the window (X or Lock), clean up and return to login
        if callable(getattr(self, "on_lock_cb", None)):
            try:
                if getattr(self, "vault", None) and getattr(self.vault, "conn", None):
                    self.vault.conn.commit()
            except Exception:
                pass
            try:
                if getattr(self, "vault", None) and getattr(self.vault, "conn", None):
                    self.vault.conn.close()
            except Exception:
                pass
            self.on_lock_cb()
        event.accept()


# --------------- Standalone run (optional) ---------------
def _demo_run_without_login():
    app = QtWidgets.QApplication(sys.argv)
    QtWidgets.QMessageBox.information(None, "Info", "Open via login.py in normal use.")
    sys.exit(0)

if __name__ == "__main__":
    _demo_run_without_login()
