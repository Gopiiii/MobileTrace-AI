"""Strict monochrome (black, white, neutral gray) QSS stylesheet for PySide6."""

MONOCHROME_QSS = """
* {
    font-family: "Segoe UI", "Public Sans", sans-serif;
    color: #171717;
    font-size: 13px;
}
QMainWindow, QWidget {
    background-color: #FFFFFF;
}
QFrame#Sidebar {
    background-color: #FAFAFA;
    border-right: 1px solid #E5E5E5;
}
QFrame#TopBar {
    background-color: #FFFFFF;
    border-bottom: 1px solid #E5E5E5;
}
QLabel#BrandTitle {
    font-size: 16px;
    font-weight: 700;
    color: #000000;
}
QLabel#SectionHeading {
    font-size: 17px;
    font-weight: 600;
    color: #000000;
}
QLabel#MutedMeta {
    color: #525252;
    font-size: 12px;
}
QPushButton#NavButton {
    text-align: left;
    padding: 9px 12px;
    border: none;
    border-radius: 4px;
    background-color: transparent;
    color: #404040;
    font-weight: 500;
}
QPushButton#NavButton:hover {
    background-color: #F5F5F5;
    color: #000000;
}
QPushButton#NavButton[active="true"] {
    background-color: #171717;
    color: #FFFFFF;
    font-weight: 600;
}
QPushButton {
    background-color: #FFFFFF;
    border: 1px solid #D4D4D4;
    border-radius: 4px;
    padding: 7px 14px;
    color: #171717;
    font-weight: 500;
}
QPushButton:hover {
    background-color: #F5F5F5;
    border-color: #A3A3A3;
}
QPushButton#PrimaryButton {
    background-color: #171717;
    border: 1px solid #171717;
    color: #FFFFFF;
}
QPushButton#PrimaryButton:hover {
    background-color: #000000;
}
QPushButton#PrimaryButton:disabled {
    background-color: #A3A3A3;
    border-color: #A3A3A3;
    color: #FAFAFA;
}
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox {
    background-color: #FFFFFF;
    border: 1px solid #D4D4D4;
    border-radius: 4px;
    padding: 6px 8px;
    color: #171717;
}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
    border: 1px solid #171717;
}
QTableWidget {
    background-color: #FFFFFF;
    border: 1px solid #E5E5E5;
    gridline-color: #E5E5E5;
    selection-background-color: #F5F5F5;
    selection-color: #000000;
}
QHeaderView::section {
    background-color: #F5F5F5;
    color: #171717;
    font-weight: 600;
    padding: 6px 8px;
    border: none;
    border-bottom: 1px solid #D4D4D4;
    border-right: 1px solid #E5E5E5;
}
QProgressBar {
    border: 1px solid #D4D4D4;
    border-radius: 3px;
    background-color: #F5F5F5;
    text-align: center;
    height: 18px;
}
QProgressBar::chunk {
    background-color: #171717;
}
QGroupBox {
    border: 1px solid #E5E5E5;
    border-radius: 4px;
    margin-top: 12px;
    padding-top: 10px;
    font-weight: 600;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
}
"""
