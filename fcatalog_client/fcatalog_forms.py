import mutex
import sys

from idaapi import *
from idautils import *
from idc import *

from fcatalog_client.qt_backend import QT_BACKEND_PYQT5, QT_BACKEND_PYSIDE

try:
    from PyQt5 import QtWidgets
    sys.modules['__main__'].QtWidgets = QtWidgets
    from PyQt5.QtCore import (pyqtSignal as Signal, pyqtSlot as Slot, QObject, QThread, QModelIndex, Qt)
    from PyQt5.QtWidgets import (QPushButton, QLineEdit, QDialog, QWidget, QTreeWidget, QVBoxLayout, QHBoxLayout,
                                 QFormLayout, QLabel, QTreeWidgetItem, QTreeWidgetItemIterator, QProgressDialog, QTabWidget)
    QT_BACKEND = QT_BACKEND_PYQT5
except:
    from PySide import QtGui
    sys.modules['__main__'].QtGui = QtGui
    from PySide.QtCore import (Signal, Slot, QObject, QThread, QModelIndex, Qt)
    from PySide.QtGui import (QPushButton, QLineEdit, QDialog, QWidget, QTreeWidget, QVBoxLayout, QHBoxLayout,
                              QFormLayout, QLabel, QTreeWidgetItem, QTreeWidgetItemIterator, QProgressDialog, QTabWidget)
    QT_BACKEND = QT_BACKEND_PYSIDE


from ida_ts import *
import fcat_logger

# FCatalogPlugin
# Every form connected to all logic by this variable (FCatalogPlugin class)
# Variable is assigned only once, when initilizing MainCatalog
FCP = None

# It is better to make size relative later, not fixed.
btn_w = 100
btn_h = 20
tree_cmn_w = 400
edit_w = 100
edit_h = 20

#Intitlized in MainCatalog
logger = None


###Some auxiliary classes###############################
class Button(QPushButton):
    def __init__(self, text, func, w=btn_w, h=btn_h):
        QPushButton.__init__(self, text)
        self.setMinimumSize(w, h)
        self.setMaximumSize(w, h)
        self.clicked.connect(func)

class Edit(QLineEdit):
    def __init__(self, text='', w=edit_w, h=edit_h):
        QLineEdit.__init__(self, text)
        self.setMinimumSize(edit_w, edit_h)
        self.setMaximumSize(edit_w, edit_h)

class Notification(QDialog):
    def __init__(self, text, parent=None):
        QDialog.__init__(self, parent)
        layout = QVBoxLayout()
        lbl = QLabel(text)
        layout.addWidget(lbl)
        self.setLayout(layout)

# Some functions like:
# checking connection
# loading function names
# ...
# are performed in the second thread.
# This signal is used to show thread termination
# if some action in GUI should be done after task is done
# e.g. we may need to update list of names and remove duplicates
# after all names are loaded
class EndSignal(QObject):
    sig = Signal()

class IntSignal(QObject):
    sig = Signal(int)

class MultiColumnList(QTreeWidget):
    def __init__(self, columns=1, column_names=['Default']):
        QTreeWidget.__init__(self)
        self.columns = columns
        self.column_names = column_names
        self.setColumnCount(columns)
        self.setHeaderLabels(column_names)

        # It is better to make size relative later, not fixed.
        for i in xrange(columns):
            self.setColumnWidth(i, tree_cmn_w)

        # Allow to select multiple items with Ctrl and Shift
        self.setSelectionMode(self.ExtendedSelection)

    def set_on_dbl_click(self, func):
        self.doubleClicked[QModelIndex].connect(func)

    # TODO: Make this be able to work with attributes too
    def update_list(self, elems):
        """
        Updates list by adding new elements.
        Makes shure that all items in list are unique
        You can call some_lst.update_list([]) just to remove all duplicates.

        :param elems: list of TEXT elements
        """
        # Stupid algo, can be slow on big amount of data
        all_items = set()
        for e in self.all():
            all_items.add(tuple(e))

        for e in elems:
            all_items.add(tuple(e))

        self.clear_all()

        for it in all_items:
            self.add_item(list(it))

    def add_item(self, item, atrib=None):
        """
        Adds new item.

        :param item: text representation of item
        :param atrib: any object representing that item.

        """
        aitem = QTreeWidgetItem()
        aitem.setFlags(aitem.flags() | Qt.ItemIsTristate | Qt.ItemIsUserCheckable)
        aitem.setCheckState(0, Qt.Unchecked)
        if self.columns != len(item):
            logger.info("Wrong number of columns")
            return
        for i,t in enumerate(item):
            aitem.setText(i,t)

        if atrib != None:
            for i,at in enumerate(atrib):
                aitem.setData(i, Qt.UserRole, at)

        self.addTopLevelItem(aitem)

    def search(self,text):
        """
        Moves cursor to item if found
        It breaks all selected items

        :param text: text representation of item

        """
        items = self.findItems(text, Qt.MatchContains, column=0)
        # Now move to first item we found
        self.setCurrentItem(items[0], 0)

    # Iterates through some items and yilds a row of
    # text representation
    # TODO: Make this be able to work with attributes too
    # def _iter(self, flags, full):
    #     items = QTreeWidgetItemIterator(self, flags)
    #     for i in items:
    #         elem = i.value()
    #         row = []
    #         for c in xrange(self.columns):
    #             if full:
    #                 row.append(elem)
    #             else:
    #                 row.append(elem.text(c))
    #         yield row

    def _iter(self, flags, full):
        it = QTreeWidgetItemIterator(self, flags)
        elem = it.value()
        while elem is not None:
            row = []
            for c in xrange(self.columns):
                if full:
                    row.append(elem)
                else:
                    row.append(elem.text(c))
            yield row
            it += 1
            elem = it.value()


    def uncheck_all(self):
        flags = QTreeWidgetItemIterator.Checked
        it = QTreeWidgetItemIterator(self, flags)
        elem = it.value()
        while elem is not None:
            elem = it.value()
            elem.setCheckState(0, Qt.Unchecked)
            it += 1
            elem = it.value()

    def checked(self, is_full=None):
        flags = QTreeWidgetItemIterator.Checked
        for i in self._iter(flags, is_full): yield i
        
    def selected(self, is_full=None):
        flags = QTreeWidgetItemIterator.Selected
        for i in self._iter(flags, is_full): yield i

    def all(self, is_full=None):
        flags = QTreeWidgetItemIterator.All
        for i in self._iter(flags, is_full): yield i

    def clear_all(self):
        self.clear()

    def clear_selected(self):
        flags = QTreeWidgetItemIterator.Selected
        it = QTreeWidgetItemIterator(self, flags)
        elem = it.value()
        while elem is not None:
            self.takeTopLevelItem(self.indexOfTopLevelItem(elem.value()))
            it += 1
            elem = it.value()

    def clear_checked(self):
        flags = QTreeWidgetItemIterator.Checked
        it = QTreeWidgetItemIterator(self, flags)
        elem = it.value()
        while elem is not None:
            self.takeTopLevelItem(self.indexOfTopLevelItem(item.value()))
            it += 1
            elem = it.value()

class SearchableList(QWidget):
    """
    Widget that combines multi column list and search form together
    If you don't need search function use MultiColumnList
    """
    def __init__(self, columns, column_names):
        QWidget.__init__(self)
        self.layout = QVBoxLayout()

        # Create elements
        self.lst = MultiColumnList(columns, column_names)
        self.srch = Edit()
        def srch_f():
            self.lst.search(self.srch.text())
        self.srch_btn = Button('Search', srch_f)

        srch_l = QVBoxLayout()
        srch_l.addWidget(self.srch)
        srch_l.addWidget(self.srch_btn)
        srch_l.setAlignment(self.srch, Qt.AlignLeft)
        srch_l.setAlignment(self.srch_btn, Qt.AlignLeft)

        # Combine in layouts
        self.layout.addWidget(self.lst)
        self.layout.addLayout(srch_l)
        self.setLayout(self.layout)

###Main classes: all tabs and MainCatalog ###############################

class FCatalogTab(QWidget):
    def __init__(self):
        QWidget.__init__(self)
        self.name = "FCatalogTab"
        self.help_msg = "" + \
        "Below are functions matched with functions in database.\n" + \
        "Double click on a row to look at the matched function in IDB.\n" + \
        "'Rename All' will rename all function by names from database.\n" + \
        "'Clean IDB' will remove all fcatalog names from your IDB if you don't like renaming result."
        self.help = QLabel(self.help_msg)
        self.help.setAlignment(Qt.AlignCenter)
        #Initilized only once, when fill() is called
        self.initilized = 0

        # This is a main layout of all tab
        layout = QVBoxLayout()

        # Create layout with list of fuction in Database
        ################################################
        db_layout = QVBoxLayout()
        db_hdr_layout = QHBoxLayout()
        db_main_layout = QHBoxLayout()
        btn_layout1 = QVBoxLayout()

        # Create and append buttons
        btn = Button('Commit All', self.commit_all)
        btn_layout1.addWidget(btn)
        btn_layout1.setAlignment(btn, Qt.AlignLeft)
        db_hdr_layout.addLayout(btn_layout1)

        # Create and append lists
        sl = SearchableList(1, ['Functions in database'])
        self.lst_db = sl.lst
        db_main_layout.addWidget(sl)

        db_layout.addLayout(db_hdr_layout)
        db_layout.addLayout(db_main_layout)


        # Create bottom layout
        ################################################
        match_layout = QVBoxLayout()
        match_hdr_layout = QHBoxLayout()
        match_main_layout = QVBoxLayout()
        match_frm_layout = QFormLayout()
        btn_layout2 = QHBoxLayout()

        # Create horizontal row of buttons
        btn = Button('Rename All', self.rename_all)
        btn_layout2.addWidget(btn)
        btn = Button('Rename Selected', self.rename_selected)
        btn_layout2.addWidget(btn)
        btn = Button('Rename Checked', self.rename_checked)
        btn_layout2.addWidget(btn)
        btn = Button('Uncheck All', self.uncheck_all)
        btn_layout2.addWidget(btn)
        btn = Button('Match Again', self.match_all)
        btn_layout2.addWidget(btn)
        btn = Button('Clean IDB', self.clean_fcat_names)
        btn_layout2.addWidget(btn)

        # Finish bottom header
        match_hdr_layout.addLayout(btn_layout2)
        match_hdr_layout.addWidget(self.help)

        sl = SearchableList(2, ['Name in current idb', 'Name in database'])
        self.lst = sl.lst
        self.lst.set_on_dbl_click(self.func_click)
        match_main_layout.addWidget(sl)
        match_layout.addLayout(match_hdr_layout)
        match_layout.addLayout(match_main_layout)

        # Combine Top and Bottom layouts
        ################################################
        layout.addLayout(db_layout)
        layout.addLayout(match_layout)

        self.setLayout(layout)

    def clear(self):
        self.lst.clear_all()
        self.lst_db.clear_all()

    def fill(self):
        """
        Get names of functions from database
        And fills 'Functions in database' list
        """
        func_names = FCP.load_func_names()
        logger.debug("Func names: {}".format(func_names))
        for fn in func_names:
            self.lst_db.add_item([fn])


        # Fill bottom (matching) list only if there are some functions in database
        if len(func_names) != 0:
            self.match_all()

        self.initilized = 1

    @Slot()
    def commit_all(self):
        sig = EndSignal()
        def upd_lst_db():
            self.lst_db.update_list([])
        sig.sig.connect(upd_lst_db)

        def cb(cb_args, f):
            if cb_args == None:
                self.lst_db.add_item([f])
            else:
                sig = cb_args[0]
                sig.sig.emit()

        FCP.commit_funcs(cb, [sig])

    @Slot()
    def match_all(self):
        nt_msg = "" + \
        "Now plugin will attempt to match functions with functions in database." + \
        "You can continue working."

        self.progress = QProgressDialog(nt_msg, "Abort", 0, 100, self)
        self.progress.setWindowModality(Qt.NonModal)
        self.progress.setValue(0)
        self.progress.show()

        def cb(cb_args, f_name, fmatched_name, faddr, count):
            signal = cb_args[1]
            if count != -1:
                self.lst.add_item([f_name, fmatched_name], [faddr, None])
                signal.sig.emit(count)
            else:
                signal.sig.emit(-1)

        def update_prog(value):
            if value != -1:
                self.progress.setMaximum(value)
                logger.debug("{}/{}".format(self.progress.value(), value))
                self.progress.setValue(self.progress.value()+1)
            else:
                self.progress.setValue(self.progress.maximum())

        sig = IntSignal()
        sig.sig.connect(update_prog)

        FCP.find_similars(cb, [self.progress, sig])

    def rename_one_elem(self, elem):
        faddr = elem[0].data(0,Qt.UserRole)
        f_new_name = elem[1].text(1)
        MakeNameEx(faddr, str(f_new_name), 0)

    @Slot()
    def rename_all(self):
        for elem in self.lst.all(True):
            self.rename_one_elem(elem)
        self.lst.clear_all()


    @Slot()
    def rename_selected(self):
        for elem in self.lst.selected(True):
            self.rename_one_elem(elem)
        self.lst.clear_selected()


    @Slot()
    def rename_checked(self):
        for elem in self.lst.checked(True):
            self.rename_one_elem(elem)
        self.lst.clear_checked()

    @Slot()
    def clean_fcat_names(self):
        logger.debug("Clean names!")
        FCP.clean_fcat_names()

    @Slot()
    def uncheck_all(self):
        self.lst.uncheck_all()


    @Slot()
    def func_click(self, index):
        model = index.model()
        fname = model.data(index)
        addr = idc.LocByName(str(fname))

        # Move cursor to function
        idc.Jump(addr)

class SCatalogTab(QWidget):
    def __init__(self):
        QWidget.__init__(self)
        self.name = "SCatalogTab"
        self.help_msg = "" + \
        "Here you can synchronize structures in the IDB and in the database.\n" 
        self.help = QLabel(self.help_msg)
        self.help.setAlignment(Qt.AlignCenter)
        #Initilized only once, when fill() is called
        self.initilized = 0

        layout = QVBoxLayout()
        hdr_layout = QHBoxLayout()
        btn_layout1 = QVBoxLayout()
        btn_layout2 = QVBoxLayout()

        # Create layout with two lists
        ################################################
        # Create lists of Structures
        lists_layout = QHBoxLayout()
        sl1 = SearchableList(1, ['Current IDB (Structures for commiting)'])
        self.lst_c = sl1.lst
        sl2 = SearchableList(1, ['Database (Structures for importing)'])
        self.lst_db = sl2.lst

        # Create header layout with buttons and help message
        ################################################
        # First columns of buttons
        btn = Button('Commit All', self.commit_all)
        btn_layout1.addWidget(btn)
        btn = Button('Commit Selected', self.commit_selected)
        btn_layout1.addWidget(btn)
        btn = Button('Commit Checked', self.commit_checked)
        btn_layout1.addWidget(btn)
        btn = Button('Uncheck All', self.lst_c.uncheck_all)
        btn_layout1.addWidget(btn)

        # Second columns of buttons
        btn = Button('Import All', self.import_all)
        btn_layout2.addWidget(btn)
        btn = Button('Import Selected', self.import_selected)
        btn_layout2.addWidget(btn)
        btn = Button('Import Checked', self.import_checked)
        btn_layout2.addWidget(btn)
        btn = Button('Uncheck All', self.lst_db.uncheck_all)
        btn_layout2.addWidget(btn)

        # Finish header layout
        hdr_layout.addLayout(btn_layout1)
        hdr_layout.addLayout(btn_layout2)
        hdr_layout.addWidget(self.help)


        # Finish lists layout
        lists_layout.addWidget(sl1)
        lists_layout.addWidget(sl2)


        # Combine all layouts
        ################################################
        layout.addLayout(hdr_layout)
        layout.addLayout(lists_layout)

        # And apply
        self.setLayout(layout)

    def clear(self):
        self.lst_c.clear_all()
        self.lst_db.clear_all()

    # Fill may consume a lot of time to return because 
    # it needs to connect to datbase and get names of structures.
    def fill(self):
        # Local structs should load fast
        for s in Structs():
            sname = s[2]
            self.lst_c.add_item([sname])

        struct_names = FCP.load_struct_names()
        for sname in struct_names:
            self.lst_db.add_item([sname])
        self.initilized = 1


    ###Commiting###############################

    def commit_bunch(self, struct_names):
        """
        Commits a bunch of structures, updating list of structures
        in the database list.

        It doesn't check if all structures successfully uploaded
        """
        FCP._fcc.commit_structs_by_names(struct_names)
        update_st_names = []
        for st_name in struct_names:
            update_st_names.append([st_name])
        self.lst_db.update_list(update_st_names)
        

    def commit_all(self):
        struct_names = []
        for elem in self.lst_c.all():
            # str() it, because unicode names crash something
            struct_names.append(str(elem[0]))

        self.commit_bunch(struct_names)

    def commit_selected(self):
        struct_names = []
        for elem in self.lst_c.selected():
            # str() it, because unicode names crash something
            struct_names.append(str(elem[0]))

        self.commit_bunch(struct_names)

    def commit_checked(self):
        struct_names = []
        for elem in self.lst_c.checked():
            # str() it, because unicode names crash something
            struct_names.append(str(elem[0]))

        self.commit_bunch(struct_names)

    ###Importing###############################

    def _create_import_pbar(self, maximum):
        progress = QProgressDialog("Importing structures...", "Abort", 0, maximum, self)
        progress.setWindowModality(Qt.WindowModal)
        progress.setValue(0)
        return progress

    def import_bunch(self, struct_names):
        progress = self._create_import_pbar(len(struct_names))
        progress.show()

        def cb(cb_args):
            progress = cb_args[0]
            progress.setValue(progress.value()+1)

        cb_args = (progress,)
        # Executes in the main thread
        FCP._fcc.load_structs_by_names(struct_names, cb, cb_args)

        update_st_names = []
        for elem in struct_names:
            update_st_names.append([elem])
        self.lst_c.update_list(update_st_names)


    def import_all(self):
        struct_names = []
        for elem in self.lst_db.all():
            struct_names.append(str(elem[0]))
        self.import_bunch(struct_names)


    def import_selected(self):
        struct_names = []
        for elem in self.lst_db.selected():
            struct_names.append(str(elem[0]))
        self.import_bunch(struct_names)


    def import_checked(self):
        struct_names = []
        for elem in self.lst_db.checked():
            struct_names.append(str(elem[0]))
        self.import_bunch(struct_names)

class ConfigureTab(QWidget):
    def __init__(self, main_frm):
        QWidget.__init__(self)
        self.name = "ConfigureTab"
        self.initilized = 0
        self.main_frm = main_frm

        self.layout = QHBoxLayout()
        self.form_layout = QFormLayout()

        # Create form layout
        ################################################
        # Create edits
        self.host_edit = Edit()
        self.port_edit = Edit()
        self.db_edit = Edit()
        self.patt_edit = Edit()
        self.sim_grade_edit = Edit()

        # Combine edits in single form
        self.form_layout.addRow('Host', self.host_edit)
        self.form_layout.addRow('Port', self.port_edit)
        self.form_layout.addRow('Database', self.db_edit)
        self.form_layout.addWidget(QLabel("FCatalog settings"))
        self.form_layout.addRow('Similarity Grade', self.sim_grade_edit)
        self.form_layout.addRow('[Optional] Exclude Pattern', self.patt_edit)

        btn = Button('Save', self.save_configuration)
        self.form_layout.addWidget(btn)

        # Combine all layouts
        ################################################
        self.layout.addLayout(self.form_layout)

        self.setLayout(self.layout)

    def fill(self):
        # Check if config already exists
        cf = FCP._client_config
        if cf != None:
            rhost = str(cf.remote_host) if cf.remote_host else ''
            rport = str(cf.remote_port) if cf.remote_port else ''
            db_name = str(cf.db_name) if cf.db_name else ''
            ex_patt = str(cf.exclude_pattern) if cf.exclude_pattern else ''
        else:
            rhost = rport = db_name = ex_patt = ''

        fc_cfg = FCP._fc_cfg
        if fc_cfg != None:
            ex_patt = str(fc_cfg.exclude_pattern) if fc_cfg.exclude_pattern else ''
            sim_grade = str(fc_cfg.sim_grade) if fc_cfg.sim_grade else ''
        else:
            ex_patt = sim_grade = ''
        
        self.host_edit.setText(rhost)
        self.port_edit.setText(rport)
        self.db_edit.setText(db_name)
        self.patt_edit.setText(ex_patt)
        self.sim_grade_edit.setText(sim_grade)

    def save_configuration(self, *args):
        host = self.host_edit.text()
        port = self.port_edit.text()
        db = self.db_edit.text()
        patt = self.patt_edit.text()
        sim_grade = self.sim_grade_edit.text()

        logger.debug("{} {} {} {} {}".format(host, port, db, patt, sim_grade))

        # Configuration validation goes here
        # If config invalid message will appear in output window
        is_config_new = FCP.create_configuration(host, port, db, patt, sim_grade)

        # Update all tabs and make them uninitilized
        # Because if general configuration is new (database, or host:port)
        # We need redownload functions and structures names
        if is_config_new:
            self.main_frm.uninitilize_tabs()



class MainCatalog(PluginForm):
    def __init__(self, fcp):
        PluginForm.__init__(self)
        global FCP
        FCP = fcp
        global logger
        logger = fcat_logger.logger

    def OnCreate(self, form):
        if QT_BACKEND == QT_BACKEND_PYQT5:
            self.parent = self.FormToPyQtWidget(form)
        else:
            self.parent = self.FormToPySideWidget(form)
        #logger.info("HELLLOOOOOOOOOO!")

        layout = QVBoxLayout()
        # Place for all tabs
        # The signal PySide.QtGui.QTabWidget.currentChanged() is emitted when the user selects a page.
        # The current page widget can be obtained with PySide.QtGui.QTabWidget.currentWidget()
        self.tabs = QTabWidget()
        self.tabs.currentChanged.connect(self.change_func)

        # Create tabs
        ################################################
        self.fcat_tab = FCatalogTab()
        self.scat_tab = SCatalogTab()
        self.conf_tab = ConfigureTab(self)

        self.tabs.addTab(self.conf_tab, "Configure")
        self.tabs.addTab(self.fcat_tab, "FCatalog")
        self.tabs.addTab(self.scat_tab, "SCatalog")


        # Combine all layouts
        ################################################
        layout.addWidget(self.tabs)

        self.parent.setLayout(layout)

    def OnClose(self, form):
        pass

    def change_func(self, index):
        tab = self.tabs.widget(index)
        if tab.initilized == 0:
            tab.fill()

    def close_popup(self):
        logger.debug("Start to close popup()")
        if self.tmp_frm and not self.blocked_m.testandset():
            self.tmp_frm.reject()
            self.tmp_frm = None
    
    def block_by_popup(self):
        # If blocked_m mutex is locked (i.e. time consuming operation is not done yet)
        if self.tmp_frm and self.blocked_m.testandset():
            logger.debug("Blocking by popup {}".format(self.blocked_m.test()))
            # This command blocks all application
            # while popup window is alive
            self.tmp_frm.exec_()
            logger.debug("Exit from exec_")
            self.tmp_frm = None
            self.blocked_m.unlock()

    def check_conn(self):
        # tmp_frm must be saved as class member because if not
        # than dialog will be created and closed right off.
        self.tmp_frm = ConnCheckerWindow(self.parent)
        self.blocked_m = mutex.mutex()

        # Again, all elements which may be refferenced by someone
        # after exiting from function must be alive (i.e they must be
        # saved in global variable or class member
        self.connt = ConnCheckerThread(FCP._fcc, self.blocked_m)
        self.connt.end_sig.sig.connect(self.close_popup)
        self.connt.start()
        self.block_by_popup()

        if self.connt.result == False:
            rhost = FCP._client_config.remote_host
            rport = FCP._client_config.remote_port
            self.ec = ConnCheckerError(rhost, rport)
            self.ec.show()

        return self.connt.result

    def uninitilize_tabs(self):
        # 1 is Func tab, 2 is Struct tab
        tab = self.tabs.widget(1)
        tab.clear()
        tab.initilized = 0

        tab = self.tabs.widget(2)
        tab.clear()
        tab.initilized = 0
        

class ConnCheckerWindow(QDialog):
    def __init__(self, parent):
        QDialog.__init__(self, parent)
        layout = QVBoxLayout()
        lbl = QLabel("Checking connection, please wait...")
        layout.addWidget(lbl)
        self.setLayout(layout)


class ConnCheckerThread(QThread):
    def __init__(self, fcc, m, parent=None):
        QThread.__init__(self, parent)
        self.fcc = fcc
        self.mtx = m
        self.end_sig = EndSignal()
        self.result = False

    def run(self):
        self.result = self.fcc._check_connection_single_thread()
        self.end_sig.sig.emit()

class ConnCheckerError(QDialog):
    def __init__(self, rhost, rport, parent=None):
        QDialog.__init__(self, parent)
        layout = QVBoxLayout()
        lbl = QLabel("Failed to connect to server (Host: {} and Port: {})\n\
Check that fcatalog_server is running and your configuration is valid.".format(rhost, rport))
        layout.addWidget(lbl)
        self.setLayout(layout)
        
