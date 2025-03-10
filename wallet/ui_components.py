import os
from PySide6.QtWidgets import (
    QPushButton, QLabel, QLineEdit, QTextEdit, QGraphicsDropShadowEffect,
    QToolButton, QMenu
)
from PySide6.QtCore import (
    Qt, QPropertyAnimation, QEasingCurve, QPoint
)
from PySide6.QtGui import (
    QPixmap, QColor, QPainter, QFont
)
from PySide6 import QtSvg

from wallet.constants import PRIMARY_BLUE, ACCENT_BLUE, TEXT_COLOR, TITLE_TEXT_COLOR, BUTTON_RADIUS, WIDGET_RADIUS, FONT_FAMILY, IMG_FOLDER


# --- Image Loading and Scaling ---
def load_and_scale_image(path: str, size: int, keep_aspect: bool = True) -> QPixmap:
    """Loads and scales an image (SVG or raster) to a QPixmap."""
    if not isinstance(path, str) or not path: # Input validation
        raise ValueError("Image path must be a non-empty string.")
    if not isinstance(size, int) or size <= 0:
        raise ValueError("Size must be a positive integer.")

    full_path = os.path.join(IMG_FOLDER, path)

    if not os.path.exists(full_path):
        pixmap = QPixmap(size, size)
        pixmap.fill(QColor(ACCENT_BLUE)) # Default to accent blue if image not found
        return pixmap

    if full_path.endswith('.svg'):
        renderer = QtSvg.QSvgRenderer(full_path)
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.GlobalColor.transparent) # Ensure SVG backgrounds are transparent
        painter = QPainter(pixmap)
        renderer.render(painter)
        painter.end()
    else:
        pixmap = QPixmap(full_path)

    if keep_aspect:
        return pixmap.scaled(size, size,
                           Qt.AspectRatioMode.KeepAspectRatio,
                           Qt.TransformationMode.SmoothTransformation)
    return pixmap.scaled(size, size,
                        Qt.AspectRatioMode.IgnoreAspectRatio,
                        Qt.TransformationMode.SmoothTransformation)


# --- Custom UI Widgets ---
class RoundedButton(QPushButton):
    """Custom rounded button with hover and press animations."""
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        font = QFont(FONT_FAMILY) # Use global font family
        self.setFont(font)
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {PRIMARY_BLUE};
                color: white;
                font-size: 14px;
                padding: 6px 15px;
                border-radius: {BUTTON_RADIUS};
                font-family: {FONT_FAMILY};
                border: none;
            }}
            QPushButton:hover {{
                background-color: {ACCENT_BLUE};
            }}
            QPushButton:pressed {{
                background-color: #0288D1;
            }}
        """)
        # Hover Animation
        self.animation_hover = QPropertyAnimation(self, b"pos")
        self.animation_hover.setDuration(100)
        self.animation_hover.setEasingCurve(QEasingCurve.Type.OutCubic)
        # Pressed Animation
        self.animation_pressed = QPropertyAnimation(self, b"pos")
        self.animation_pressed.setDuration(50)
        self.animation_pressed.setEasingCurve(QEasingCurve.Type.OutCubic)
        # Drop Shadow Effect
        self.shadow_effect = QGraphicsDropShadowEffect(self)
        self.shadow_effect.setBlurRadius(10)
        self.shadow_effect.setColor(QColor(0, 0, 0, 60))
        self.shadow_effect.setOffset(0, 3)
        self.setGraphicsEffect(self.shadow_effect)
        self.setCursor(Qt.CursorShape.PointingHandCursor) # Set cursor for buttons

    def enterEvent(self, event):
        current_pos = self.pos()
        self.animation_hover.setStartValue(current_pos)
        self.animation_hover.setEndValue(QPoint(current_pos.x(), current_pos.y() - 2))
        self.animation_hover.start()
        super().enterEvent(event)

    def leaveEvent(self, event):
        current_pos = self.pos()
        self.animation_hover.setStartValue(current_pos)
        self.animation_hover.setEndValue(QPoint(current_pos.x(), current_pos.y() + 2))
        self.animation_hover.start()
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        current_pos = self.pos()
        self.animation_pressed.setStartValue(current_pos)
        self.animation_pressed.setEndValue(QPoint(current_pos.x(), current_pos.y() + 1))
        self.animation_pressed.start()
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        current_pos = self.pos()
        self.animation_pressed.setStartValue(current_pos)
        self.animation_pressed.setEndValue(QPoint(current_pos.x(), current_pos.y() - 1))
        self.animation_pressed.start()
        super().mouseReleaseEvent(event)


class SecondaryButton(QPushButton):
    """Custom secondary style button."""
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        font = QFont(FONT_FAMILY) # Use global font family
        self.setFont(font)
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: white;
                color: {TEXT_COLOR};
                font-size: 14px;
                padding: 6x 15px;
                border-radius: {BUTTON_RADIUS};
                border: 1px solid #B0BEC5;
                font-family: {FONT_FAMILY};
            }}
            QPushButton:hover {{
                background-color: #ECEFF1;
            }}
            QPushButton:pressed {{
                background-color: #CFD8DC;
            }}
        """)
        # Hover Animation
        self.animation_hover = QPropertyAnimation(self, b"pos")
        self.animation_hover.setDuration(100)
        self.animation_hover.setEasingCurve(QEasingCurve.Type.OutCubic)
        # Pressed Animation
        self.animation_pressed = QPropertyAnimation(self, b"pos")
        self.animation_pressed.setDuration(50)
        self.animation_pressed.setEasingCurve(QEasingCurve.Type.OutCubic)
        # Drop Shadow Effect
        self.shadow_effect = QGraphicsDropShadowEffect(self)
        self.shadow_effect.setBlurRadius(5) # Less blur for secondary
        self.shadow_effect.setColor(QColor(0, 0, 0, 40)) # Lighter shadow
        self.shadow_effect.setOffset(0, 2)
        self.setGraphicsEffect(self.shadow_effect)
        self.setCursor(Qt.CursorShape.PointingHandCursor) # Set cursor for buttons

    def enterEvent(self, event):
        current_pos = self.pos()
        self.animation_hover.setStartValue(current_pos)
        self.animation_hover.setEndValue(QPoint(current_pos.x(), current_pos.y() - 2))
        self.animation_hover.start()
        super().enterEvent(event)

    def leaveEvent(self, event):
        current_pos = self.pos()
        self.animation_hover.setStartValue(current_pos)
        self.animation_hover.setEndValue(QPoint(current_pos.x(), current_pos.y() + 2))
        self.animation_hover.start()
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        current_pos = self.pos()
        self.animation_pressed.setStartValue(current_pos)
        self.animation_pressed.setEndValue(QPoint(current_pos.x(), current_pos.y() + 1))
        self.animation_pressed.start()
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        current_pos = self.pos()
        self.animation_pressed.setStartValue(current_pos)
        self.animation_pressed.setEndValue(QPoint(current_pos.x(), current_pos.y() - 1))
        self.animation_pressed.start()
        super().mouseReleaseEvent(event)


class TitleLabel(QLabel):
    """Custom title label style."""
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont(FONT_FAMILY, 28, QFont.Weight.Bold) # Use global font family, size, and bold
        self.setFont(font)
        self.setStyleSheet(f"""
            QLabel {{
                color: {TITLE_TEXT_COLOR};
                font-size: 28px;
                font-weight: 800;
                font-family: {FONT_FAMILY};
                text-decoration: none;
                border: none;
            }}
        """)

class HeadlineLabel(QLabel):
    """Custom headline label style."""
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)  # Add center alignment
        font = QFont(FONT_FAMILY, 22, QFont.Weight.Bold) # Use global font family, size, and bold
        self.setFont(font)
        self.setStyleSheet(f"""
            QLabel {{
                color: {TEXT_COLOR};
                font-size: 22px;
                font-weight: bold;
                font-family: {FONT_FAMILY};
            }}
        """)

class BodyLabel(QLabel):
    """Custom body label style."""
    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont(FONT_FAMILY, 16) # Use global font family and size
        self.setFont(font)
        self.setStyleSheet(f"""
            QLabel {{
                color: {TEXT_COLOR};
                font-size: 16px;
                font-family: {FONT_FAMILY};
            }}
        """)

class SeedPhraseBox(QLabel):
    """Custom label for displaying seed phrases."""
    def __init__(self, parent=None):
        super().__init__(parent)
        font = QFont("Monospace", 18) # Monospace for seed phrases
        self.setFont(font)
        self.setStyleSheet(f"""
            QLabel {{
                font-family: monospace;
                font-size: 18px;
                border: 2px solid {ACCENT_BLUE};
                padding: 15px;
                border-radius: {WIDGET_RADIUS};
                background-color: white;
                color: {TEXT_COLOR};
            }}
        """)

class RoundedLineEdit(QLineEdit):
    """Custom rounded line edit."""
    def __init__(self, parent=None):
        super().__init__(parent)
        font = QFont(FONT_FAMILY, 16) # Use global font family and size
        self.setFont(font)
        self.setStyleSheet(f"""
            QLineEdit {{
                background-color: white;
                color: {TEXT_COLOR};
                border: 1px solid #B0BEC5;
                border-radius: {WIDGET_RADIUS};
                padding: 10px;
                font-size: 16px;
                font-family: {FONT_FAMILY};
            }}
        """)

class RoundedTextEdit(QTextEdit):
    """Custom rounded text edit."""
    def __init__(self, parent=None):
        super().__init__(parent)
        font = QFont(FONT_FAMILY, 16) # Use global font family and size
        self.setFont(font)
        self.setStyleSheet(f"""
            QTextEdit {{
                background-color: white;
                color: {TEXT_COLOR};
                border: 1px solid #B0BEC5;
                border-radius: {WIDGET_RADIUS};
                padding: 10px;
                font-size: 16px;
                font-family: {FONT_FAMILY};
            }}
        """)

class QRCodeLabel(QLabel):
    """Custom QLabel for clickable QR code with zoom."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet("""
            QLabel {
                background-color: white;
                border-radius: 10px;
                padding: 10px;
                border: 1px solid #B0BEC5;
            }
            QLabel:hover {
                background-color: #ECEFF1;
            }
        """)

class AddressDropdown(QToolButton):
    """Custom dropdown for address display."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QToolButton {{
                background-color: transparent;
                text-align: center;  // changed from left to center
                font-family: {FONT_FAMILY};
                padding-right: 15px; /* Space for the arrow */
            }}
            QToolButton::menu-indicator {{
                image: none; /* Remove default indicator */
                subcontrol-position: right center;
                subcontrol-origin: padding;
                right: 5px;
            }}
            QToolButton::menu-button {{
                width: 15px; /* Width for custom arrow */
                border-left: 1px solid gray; /* Optional separator */
            }}
            QToolButton:hover {{
                background-color: #ECEFF1;
            }}
        """)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.address = ""
        self.menu = QMenu(self) # Create menu
        copy_action = self.menu.addAction("Copy Address") # Actions for menu
        view_etherscan_action = self.menu.addAction("View on Etherscan")
        copy_action.triggered.connect(self.copy_address) # Connect actions
        view_etherscan_action.triggered.connect(self.view_on_etherscan)
        self.setMenu(self.menu) # Set menu to toolbutton
        self.setPopupMode(QToolButton.InstantPopup) # Show menu on click


    def setAddress(self, address):
        """Sets the displayed address and updates tooltip and text."""
        self.address = address
        truncated = f"{address[:6]}...{address[-4:]}" if address else "N/A"
        self.setText(f"🔑 {truncated}")
        self.setToolTip(address if address else "No address available")

    def copy_address(self):
        """Copies address to clipboard."""
        if self.address:
            from PySide6.QtWidgets import QApplication, QMessageBox # Import here to avoid circular import in main if directly used there.
            QApplication.clipboard().setText(self.address)
            QMessageBox.information(self, "Copied", "Address copied to clipboard!")

    def view_on_etherscan(self):
        """Opens the address on Etherscan in the default browser."""
        if self.address:
            from PySide6.QtGui import QDesktopServices
            from PySide6.QtCore import QUrl
            etherscan_url = f"https://etherscan.io/address/{self.address}"
            QDesktopServices.openUrl(QUrl(etherscan_url))
