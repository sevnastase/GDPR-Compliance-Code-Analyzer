# coding=utf-8

"""Plugin global settings.

Covers the plugin global settings which a user can set and save. The settings
will be saved using QgsSettings. Settings can be accessed via the QGIS options,
a button on the docking widget, and from the toolbar menu.
"""

import os
import typing
import uuid

import qgis.core
import qgis.gui

from qgis.analysis import QgsAlignRaster

from qgis.gui import QgsFileWidget, QgsOptionsPageWidget
from qgis.gui import QgsOptionsWidgetFactory
from qgis.PyQt import uic, QtWidgets
from qgis.PyQt.QtGui import (
    QIcon,
    QShowEvent,
)
from qgis.utils import iface

from qgis.PyQt.QtWidgets import (
    QFileDialog,
    QListWidgetItem,
    QMessageBox,
    QWidget,
    QHeaderView,
    QFileDialog,
)
from qgis.PyQt import QtCore
from qgis.PyQt.QtGui import QStandardItemModel, QStandardItem
from qgis.PyQt.QtCore import Qt, QSortFilterProxyModel

from ...api.base import ApiRequestStatus
from ...api.carbon import (
    start_irrecoverable_carbon_download,
    get_downloader_task,
)
from ...api.layer_tasks import DeleteDefaultLayerTask
from ...conf import (
    settings_manager,
    Settings,
)
from ...models.base import DataSourceType
from ...definitions.constants import CPLUS_OPTIONS_KEY
from ...definitions.defaults import (
    GENERAL_OPTIONS_TITLE,
    ICON_PATH,
    OPTIONS_TITLE,
)
from ...lib.validation.configs import (
    no_data_validation_config,
    projected_crs_validation_config,
    raster_validation_config,
)
from ...lib.validation.feedback import ValidationFeedback
from ...lib.validation.validators import DataValidator
from ...models.validation import RuleInfo, RuleType
from ...models.base import DataSourceType, LayerModelComponent, LayerType
from ...trends_earth.constants import API_URL, TIMEOUT
from ...utils import FileUtils, log, tr, convert_size
from ...trends_earth import auth, api, download
from ...api.request import CplusApiRequest

from .priority_layer_add import DlgPriorityAddEdit

Ui_DlgSettings, _ = uic.loadUiType(
    os.path.join(os.path.dirname(__file__), "../../ui/cplus_settings.ui")
)
Ui_TrendsEarthDlgSettingsLogin, _ = uic.loadUiType(
    os.path.join(os.path.dirname(__file__), "../../ui/trends_earth_login.ui")
)
Ui_TrendsEarthDlgSettingsEditForgotPassword, _ = uic.loadUiType(
    os.path.join(os.path.dirname(__file__), "../../ui/trends_earth_forgot_password.ui")
)
Ui_TrendsEarthSettingsRegister, _ = uic.loadUiType(
    os.path.join(os.path.dirname(__file__), "../../ui/trends_earth_register.ui")
)
Ui_TrendsEarthSettingsEditUpdate, _ = uic.loadUiType(
    os.path.join(os.path.dirname(__file__), "../../ui/trends_earth_edit_update.ui")
)


settings = QtCore.QSettings()


class tr_settings(QtCore.QObject):
    def tr(txt):
        return QtCore.QCoreApplication.translate(self.__class__.__name__, txt)


# Function to indicate if child is a folder within parent
def is_subdir(child, parent):
    parent = os.path.normpath(os.path.realpath(parent))
    child = os.path.normpath(os.path.realpath(child))

    if not os.path.isdir(parent) or not os.path.isdir(child):
        return False
    elif child == parent:
        return True
    head, tail = os.path.split(child)

    if head == parent:
        return True
    elif tail == "":
        return False
    else:
        return is_subdir(head, parent)


def _get_user_email(auth_setup, warn=True):
    """get user email for a particular service from authConfig"""
    authConfig = auth.get_auth_config(auth_setup, warn=warn)
    if not authConfig:
        return None

    email = authConfig.config("username")
    log(email)
    log(authConfig.config("password"))
    if warn and email is None:
        QtWidgets.QMessageBox.critical(
            None,
            tr_settings.tr("Error"),
            tr_settings.tr(
                "Please setup access to {auth_setup.name} before "
                "using this function."
            ),
        )
        return None
    else:
        return email


class DlgSettingsRegister(QtWidgets.QDialog, Ui_TrendsEarthSettingsRegister):
    authConfigInitialised = QtCore.pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setupUi(self)

        self.admin_bounds_key = download.get_admin_bounds()
        self.country.addItems(sorted(self.admin_bounds_key.keys()))

        self.buttonBox.accepted.connect(self.register)
        self.buttonBox.rejected.connect(self.close)

        self.trends_earth_api_client = api.APIClient(API_URL, TIMEOUT)

    def register(self):
        if not self.email.text():
            QtWidgets.QMessageBox.critical(
                None, self.tr("Error"), self.tr("Enter your email address.")
            )

            return
        elif not self.name.text():
            QtWidgets.QMessageBox.critical(
                None, self.tr("Error"), self.tr("Enter your name.")
            )

            return
        elif not self.organization.text():
            QtWidgets.QMessageBox.critical(
                None, self.tr("Error"), self.tr("Enter your organization.")
            )

            return
        elif not self.country.currentText():
            QtWidgets.QMessageBox.critical(
                None, self.tr("Error"), self.tr("Enter your country.")
            )

            return

        resp = self.trends_earth_api_client.register(
            self.email.text(),
            self.name.text(),
            self.organization.text(),
            self.country.currentText(),
        )

        if resp:
            self.close()
            if resp.get("status", 200) == 200:
                QtWidgets.QMessageBox.information(
                    None,
                    self.tr("Success"),
                    self.tr(
                        "User registered. Your password "
                        f"has been emailed to {self.email.text()}. "
                        "Enter that password in CPLUS settings "
                        "to finish setting up the plugin."
                    ),
                )
                # add a new auth conf that have to be completed with pwd
                authConfigId = auth.init_auth_config(
                    auth.TE_API_AUTH_SETUP, email=self.email.text()
                )

                if authConfigId:
                    self.authConfigInitialised.emit(authConfigId)
                    return authConfigId
            else:
                QtWidgets.QMessageBox.information(
                    None,
                    self.tr("Registration failed"),
                    self.tr(resp.get("detail", "")),
                )
        else:
            QtWidgets.QMessageBox.information(
                None,
                self.tr("Failed"),
                self.tr(
                    "Failed to register. Please check your internet connection and try again."
                ),
            )
            return None


class DlgSettingsLogin(QtWidgets.QDialog, Ui_TrendsEarthDlgSettingsLogin):
    def __init__(self, parent=None, main_widget=None):
        super().__init__(parent)

        self.setupUi(self)

        self.buttonBox.accepted.connect(self.login)
        self.buttonBox.rejected.connect(self.close)

        self.ok = False
        self.trends_earth_api_client = api.APIClient(API_URL, TIMEOUT)
        self.main_widget = main_widget
        self.parent = parent

    def showEvent(self, event):
        super().showEvent(event)

        email = _get_user_email(auth.TE_API_AUTH_SETUP, warn=False)

        if email:
            self.email.setText(email)

    def login(self):
        if not self.email.text():
            QtWidgets.QMessageBox.critical(
                None, self.tr("Error"), self.tr("Enter your email address.")
            )

            return
        elif not self.password.text():
            QtWidgets.QMessageBox.critical(
                None, self.tr("Error"), self.tr("Enter your password.")
            )

            return

        if self.trends_earth_api_client.login_test(
            self.email.text(), self.password.text()
        ):
            QtWidgets.QMessageBox.information(
                None,
                self.tr("Success"),
                self.tr(
                    "Logged in to the CPLUS server as "
                    f"{self.email.text()}.<html><p>Welcome to "
                    "CPLUS!</p><p>You only need to login once.<p></html>"
                ),
            )
            auth.init_auth_config(
                auth.TE_API_AUTH_SETUP, self.email.text(), self.password.text()
            )

            settings_manager.delete_online_scenario()
            settings_manager.remove_default_layers()
            self.main_widget.fetch_default_layer_list()

            self.parent.enable_admin_components()
            self.main_widget.fetch_default_layer_task.task_finished.connect(
                self.parent.refresh_default_layers_table
            )

            self.main_widget.fetch_scenario_history_list()

            self.ok = True
            self.close()


class DlgSettingsEditUpdate(QtWidgets.QDialog, Ui_TrendsEarthSettingsEditUpdate):
    def __init__(self, user, parent=None):
        super().__init__(parent)

        self.setupUi(self)

        self.user = user

        self.admin_bounds_key = download.get_admin_bounds()

        self.email.setText(user["email"])
        self.name.setText(user["name"])
        self.organization.setText(user["institution"])

        # Add countries, and set index to currently chosen country
        self.country.addItems(sorted(self.admin_bounds_key.keys()))
        index = self.country.findText(user["country"])

        if index != -1:
            self.country.setCurrentIndex(index)

        self.buttonBox.accepted.connect(self.update_profile)
        self.buttonBox.rejected.connect(self.close)

        self.ok = False
        self.trends_earth_api_client = api.APIClient(API_URL, TIMEOUT)

    def update_profile(self):
        if not self.email.text():
            QtWidgets.QMessageBox.critical(
                None, self.tr("Error"), self.tr("Enter your email address.")
            )

            return
        elif not self.name.text():
            QtWidgets.QMessageBox.critical(
                None, self.tr("Error"), self.tr("Enter your name.")
            )

            return
        elif not self.organization.text():
            QtWidgets.QMessageBox.critical(
                None, self.tr("Error"), self.tr("Enter your organization.")
            )

            return
        elif not self.country.currentText():
            QtWidgets.QMessageBox.critical(
                None, self.tr("Error"), self.tr("Enter your country.")
            )

            return

        resp = self.trends_earth_api_client.update_user(
            self.email.text(),
            self.name.text(),
            self.organization.text(),
            self.country.currentText(),
        )

        if resp:
            if resp.get("status", 200) == 200:
                QtWidgets.QMessageBox.information(
                    None,
                    self.tr("Saved"),
                    self.tr("Updated information for {}.").format(self.email.text()),
                )
                self.close()
                self.ok = True
            else:
                QtWidgets.QMessageBox.information(
                    None,
                    self.tr("Failed"),
                    self.tr(resp.get("detail", "")),
                )
                self.close()
        else:
            QtWidgets.QMessageBox.information(
                None,
                self.tr("Failed"),
                self.tr(
                    "Failed to update user information. Please check your internet connection and try again."
                ),
            )


class DlgSettingsEditForgotPassword(
    QtWidgets.QDialog, Ui_TrendsEarthDlgSettingsEditForgotPassword
):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setupUi(self)

        self.buttonBox.accepted.connect(self.reset_password)
        self.buttonBox.rejected.connect(self.close)

        self.ok = False

        self.trends_earth_api_client = api.APIClient(API_URL, TIMEOUT)
