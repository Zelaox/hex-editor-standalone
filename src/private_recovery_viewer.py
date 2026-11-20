"""In-memory Qt view of authenticated current-user recovery candidates."""
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTextBrowser


def create_private_viewer(run_root, case_id, parent=None):
    from hexeditor_tools.api import _forensic_root
    from src.services.browser_forensics.private_recovery import open_payload, private_html, recovery_policy
    payload = open_payload(_forensic_root(str(run_root)), case_id)
    dialog = QDialog(parent)
    dialog.setWindowTitle(recovery_policy()["viewer_title"])
    layout = QVBoxLayout(dialog)
    browser = QTextBrowser(dialog)
    browser.setOpenLinks(False)
    browser.setOpenExternalLinks(False)
    browser.setHtml(private_html(payload))
    layout.addWidget(browser)
    return dialog
