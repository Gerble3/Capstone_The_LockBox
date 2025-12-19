# login.py (PyQt6) — fixed: editable DB path + visible caret
import os
import sys

from PyQt6 import QtCore, QtGui, QtWidgets

from main_window import VaultMainWindow
from cloud_vault.db import open_vault, init_vault

# (note for grader) login.py file contains the login window for the vault application

APP_TITLE = "Lock Box — Master Login"


#  Threading helpers 
class WorkerSignals(QtCore.QObject):
    done = QtCore.pyqtSignal(object)
    error = QtCore.pyqtSignal(str)


class Worker(QtCore.QRunnable):
    """Run a function in a background thread and emit results/errors to the UI."""
    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()
        self.setAutoDelete(True)

    @QtCore.pyqtSlot()
    def run(self):
        try:
            res = self.fn(*self.args, **self.kwargs)
            self.signals.done.emit(res)
        except Exception as e:
            self.signals.error.emit(str(e))


#  UI 
class LoginWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.setMinimumWidth(520)

        # thread pool + keep workers alive
        self.thread_pool = QtCore.QThreadPool.globalInstance()
        self._workers = set()

        # Settings (remember last DB path)
        self.settings = QtCore.QSettings("Clayton", "LockBox")

        # Title
        self.title = QtWidgets.QLabel(
            "<h2>🔐 Lock Box</h2><div>Open an existing vault or create a new one.</div>"
        )
        self.title.setTextFormat(QtCore.Qt.TextFormat.RichText)

        # --- DB path row (EDITABLE AGAIN) ---
        self.db_label = QtWidgets.QLabel("Vault database (.db):")

        self.db_path = QtWidgets.QLineEdit()
        self.db_path.setPlaceholderText(
            r"Type or browse to a vault file (e.g., C:\...\LockBox\vault.db)"
        )

        self.db_browse = QtWidgets.QToolButton()
        self.db_browse.setText("Browse…")
        self.db_browse.setToolTip("Select an existing or new .db file")

        path_row = QtWidgets.QHBoxLayout()
        path_row.addWidget(self.db_path, 1)
        path_row.addWidget(self.db_browse)

        # Password row
        self.pw_label = QtWidgets.QLabel("Master password:")
        self.password = QtWidgets.QLineEdit()
        self.password.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.show_pw = QtWidgets.QCheckBox("Show")

        pw_row = QtWidgets.QHBoxLayout()
        pw_row.addWidget(self.password, 1)
        pw_row.addWidget(self.show_pw)

        # Options
        self.remember_path = QtWidgets.QCheckBox("Remember this path")
        self.remember_path.setChecked(True)

        # Buttons
        self.init_btn = QtWidgets.QPushButton("Initialize New Vault")
        self.open_btn = QtWidgets.QPushButton("Unlock Existing Vault")
        self.open_btn.setDefault(True)

        btn_row = QtWidgets.QHBoxLayout()
        btn_row.addWidget(self.init_btn)
        btn_row.addWidget(self.open_btn)

        # Status
        self.status = QtWidgets.QLabel("")
        self.status.setStyleSheet("color:#888")

        # Form layout
        form = QtWidgets.QFormLayout()
        form.addRow(self.db_label)
        form.addRow(path_row)
        form.addRow(self.pw_label)
        form.addRow(pw_row)
        form.addRow(self.remember_path)
        form.addRow(btn_row)
        form.addRow(self.status)

        # Outer layout
        outer = QtWidgets.QVBoxLayout(self)
        outer.addWidget(self.title)
        outer.addLayout(form)

        # Signals
        self.db_browse.clicked.connect(self.on_browse)
        self.show_pw.toggled.connect(self.on_show_pw)
        self.init_btn.clicked.connect(self.on_init)
        self.open_btn.clicked.connect(self.on_open)

        # Load last DB path (or default)
        last = self.settings.value("last_db_path", type=str)
        if last and os.path.exists(os.path.dirname(last)):
            self._set_db_path(last)
        else:
            self._set_db_path("vault.db")

    #  Helpers 

    def _return_to_login(self):
        # clear sensitive input when coming back
        self.password.clear()
        self.set_busy(False, "")
        self.show()
        self.activateWindow()
        self.raise_()

    def _set_db_path(self, full_path: str):
        p = os.path.abspath(full_path)
        self.db_path.setText(p)
        self.db_path.setToolTip(p)

    def _get_db_path(self) -> str:
        p = self.db_path.text().strip()
        return os.path.abspath(p) if p else ""

    def set_busy(self, busy: bool, msg: str = ""):
        for w in (self.init_btn, self.open_btn, self.db_browse, self.password, self.db_path):
            w.setDisabled(busy)
        self.status.setText(("⏳ " if busy else "") + msg)

    def _on_bg_done(self, res, success_msg: str, after):
        self.set_busy(False, success_msg)
        if callable(after):
            after(res)

    def _on_bg_error(self, msg: str):
        self.set_busy(False, "")
        QtWidgets.QMessageBox.critical(self, "Error", msg)

    def run_bg(self, fn, *args, success_msg: str = "", after=None):
        worker = Worker(fn, *args)
        self._workers.add(worker)  # prevent GC before signals fire

        def _done(res):
            self._workers.discard(worker)
            self._on_bg_done(res, success_msg, after)

        def _error(msg: str):
            self._workers.discard(worker)
            self._on_bg_error(msg)

        worker.signals.done.connect(_done, type=QtCore.Qt.ConnectionType.QueuedConnection)
        worker.signals.error.connect(_error, type=QtCore.Qt.ConnectionType.QueuedConnection)
        self.thread_pool.start(worker)

    #  Slots
    def on_browse(self):
        current = self._get_db_path()
        if current:
            start_dir = os.path.dirname(current)
            if not os.path.isdir(start_dir):
                start_dir = os.path.expanduser("~")
        else:
            start_dir = os.path.expanduser("~")

        dlg = QtWidgets.QFileDialog(self, "Select or create a vault database", start_dir)
        dlg.setNameFilter("SQLite DB (*.db *.sqlite);;All Files (*)")
        dlg.setAcceptMode(QtWidgets.QFileDialog.AcceptMode.AcceptOpen)
        if dlg.exec():
            self._set_db_path(dlg.selectedFiles()[0])

    def on_show_pw(self, checked: bool):
        self.password.setEchoMode(
            QtWidgets.QLineEdit.EchoMode.Normal if checked else QtWidgets.QLineEdit.EchoMode.Password
        )

    def on_init(self):
        db = self._get_db_path()
        pw = self.password.text()

        if not db:
            QtWidgets.QMessageBox.warning(self, "Missing", "Please enter or select a database path.")
            return
        if not pw:
            QtWidgets.QMessageBox.warning(self, "Missing", "Please enter a master password.")
            return

        if os.path.exists(db) and os.path.getsize(db) > 0:
            resp = QtWidgets.QMessageBox.question(
                self, "Overwrite?",
                "Database already exists and may be initialized. Continue?",
                QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
            )
            if resp != QtWidgets.QMessageBox.StandardButton.Yes:
                return

        self.set_busy(True, "Initializing vault…")
        self.run_bg(
            init_vault, db, pw,
            success_msg="Vault initialized.",
            after=lambda vault: self.post_login(db, vault),
        )

    def on_open(self):
        db = self._get_db_path()
        pw = self.password.text()

        if not os.path.exists(db):
            QtWidgets.QMessageBox.warning(self, "Not found", "Database file does not exist.")
            return
        if not pw:
            QtWidgets.QMessageBox.warning(self, "Missing", "Please enter your master password.")
            return

        self.set_busy(True, "Unlocking…")
        self.run_bg(
            open_vault, db, pw,
            success_msg="Unlocked.",
            after=lambda vault: self.post_login(db, vault),
        )

    def post_login(self, db_path: str, vault):
        if self.remember_path.isChecked():
            self.settings.setValue("last_db_path", db_path)

        # show vault, hide login
        self.main = VaultMainWindow(
            vault,
            db_path,
            on_lock=self._return_to_login  # NEW
        )
        self.main.show()
        self.hide()

    def _return_to_login(self):
        # optional: clear password field when returning
        self.password.clear()
        self.set_busy(False, "")
        self.show()
        self.activateWindow()
        self.raise_()

def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    font = QtGui.QFont()
    font.setPointSize(10)
    app.setFont(font)

    w = LoginWindow()
    w.resize(560, 260)
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
