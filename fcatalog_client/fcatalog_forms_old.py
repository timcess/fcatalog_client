from idaapi import *
from idc import *
from idautils import *
import fcat_logger
from db_endpoint import NetError

class ConfForm(Form):
    def __init__(self):
        self.invert = False
        Form.__init__(self, r"""STARTITEM {id:host}
FCatalog Client Configuration

<#Host:{host}>
<#Port:{port}>
<#Database Name:{db_name}>
<#Exclude Pattern:{exclude_pattern}>
""", {
        'host': Form.StringInput(tp=Form.FT_TYPE),
        'port': Form.StringInput(tp=Form.FT_TYPE),
        'db_name': Form.StringInput(tp=Form.FT_TYPE),
        'exclude_pattern': Form.StringInput(tp=Form.FT_TYPE),
    })



class CErrorForm(Form):
    def __init__(self, host, port):
        self.form_code=r"""Connection Error


        Failed to connect to server (Host: {} and Port: {})
        Check that fcatalog_server is running and your configuration is valid.
        """.format(host, port)

        self.match = {}

        Form.__init__(self, self.form_code, self.match)

#UNUSED
class CheckConnForm(Form):
    def __init__(self, fcc, host, port):
        self.form_code=r"""BUTTON YES NONE
BUTTON NO NONE
BUTTON CANCEL NONE
        Checking connection...


        Trying to connect to server (Host: {} and Port: {})
        """.format(host, port)

        self.match = {}

        Form.__init__(self, self.form_code, self.match)




class SCatalogDatabaseChooser(Choose2):
    """
    A simple chooser to be used as an embedded chooser
    """
    def __init__(self, title, fcc, mf, nb = 5, flags=0):
        Choose2.__init__(self,
                         title,
                         [["Name", 20]],
                         embedded=True, width=50, height=30, flags=flags)

        self.main_form = mf
        self.fcc = fcc
        self.icon = 5
        self.selcount = 0

        self.make_items()

    def make_items(self):
        self.items = []
        if self.fcc is None:
            logger.info('Please configure FCatalog')
            return

        struct_names = []
        try:
            struct_names = self.fcc.load_struct_names()
        except NetError:
            struct_names = []

        for s in struct_names:
            self.items.append([s])

        self.n = len(self.items)
        fcat_logger.logger.debug(self.n)
        fcat_logger.logger.debug(self.items)

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        try:
            self.fcc.load_structs_by_names(self.items[n])
            self.main_form.cur_idb_chooser.items.append(self.items[n])
            self.main_form.RefreshField(self.main_form.curidb_chooser)
        except NetError:
            fcat_logger.logger.info("Connection with the server has been lost")

    def OnGetSize(self):
        n = len(self.items)
        return n

class SCatalogCurrentIDBChooser(Choose2):
    """
    A simple chooser to be used as an embedded chooser
    """
    def __init__(self, title, fcc, mf, nb = 5, flags=0):
        Choose2.__init__(self,
                         title,
                         [["Name", 20]],
                         embedded=True, width=50, height=30, flags=flags)

        self.fcc = fcc
        self.main_form = mf
        self.items = []
        self.make_items()
        self.icon = 5
        self.selcount = 0

    def make_items(self):
        self.items = []
        for s in Structs():
            self.items.append([s[2]])
        self.n = len(self.items)

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnSelectLine(self, n):
        if self.fcc is None:
            fcat_logger.logger.info('Please configure FCatalog')
            return

        try:
            self.fcc.commit_structs_by_names(self.items[n])
            self.main_form.database_chooser.items.append(self.items[n])
            self.main_form.RefreshField(self.main_form.db_chooser)
        except NetError:
            fcat_logger.logger.info('Connection with the server have been lost')
            

    def OnGetSize(self):
        n = len(self.items)
        return n

class SCatalogForm(Form):
    def __init__(self, fcc):
        self.fcc = fcc
        self.cur_idb_chooser = SCatalogCurrentIDBChooser("E1", fcc, self, flags=Choose2.CH_MULTI)

        # GUI will hang if no connecton to server
        # but connectino was checked in _scatalog()
        self.database_chooser = SCatalogDatabaseChooser("E2", fcc, self, flags=Choose2.CH_MULTI)
        self.hhelp = "a"*340

        self.form_code = r"""BUTTON YES NONE
BUTTON NO NONE
BUTTON CANCEL OK
HELP
You can search structures in each list by pressing Ctrl+F.
Double click on a structure to commit/import it
For a while all commiting and importing done in synchronous mode, so be patient!
ENDHELP
SCatalog

Press Ctrl+F for searching
Double click on a structure to commit/import it


{FormChangeCb}
<Current IDB:{curidb_chooser}> <Database:{db_chooser}>
<##Commit all     :{commitAllBtn}>
<##Commit selected:{commitSelected}>
<##Import all     :{importAllBtn}>
<##Import selected:{importSelected}>
"""

        self.match = {
        'commitAllBtn':Form.ButtonInput(self.commit_all_button),
        'importAllBtn':Form.ButtonInput(self.import_all_button),
        'commitSelected':Form.ButtonInput(self.commit_selected_button),
        'importSelected':Form.ButtonInput(self.import_selected_button),
        'curidb_chooser':Form.EmbeddedChooserControl(self.cur_idb_chooser),
        'db_chooser':Form.EmbeddedChooserControl(self.database_chooser),
        'FormChangeCb': Form.FormChangeCb(self.OnFormChange)
        }

        Form.__init__(self, self.form_code, self.match)

    def commit_all_button(self, code=0):
        try:
            self.fcc.commit_structs()
            # Update Database chooser to display commited structures
            # !!!!
            # No checking here, if these structuress succesfully dumped on server
            # !!!!
            for s in Structs():
                fcat_logger.logger.debug("Adding {} to database_chooser".format(s[2]))
                self.database_chooser.items.append([s[2]])

            ret = self.RefreshField(self.db_chooser)
        except NetError:
            fcat_logger.logger.info('Connection with the server have been lost')


    def commit_selected_button(self, code=0):
        items = self.cur_idb_chooser.items

        struct_names = []
        for index in self.cur_idb_struct_choosed:
            struct_names.append(items[index][0])

        try:
            self.fcc.commit_structs_by_names(struct_names)
            # Update Database chooser to display commited structures
            # !!!!
            # No checking here, if these structuress succesfully dumped on server
            # !!!!
            for s in struct_names:
                self.database_chooser.items.append([s])

            self.RefreshField(self.db_chooser)
        except NetError:
            fcat_logger.logger.info('Connection with the server have been lost')


    def import_all_button(self, code=0):
        try:
            self.fcc.load_all_structs()
            # Update currend IDB chooser to display commited structures
            # !!!!
            # No checking here, if these structuress succesfully dumped on server
            # !!!!
            for s in Structs():
                self.cur_idb_chooser.items.append([s[2]])

            ret = self.RefreshField(self.curidb_chooser)
        except NetError:
            fcat_logger.logger.info('Connection with the server have been lost')


    def import_selected_button(self, code=0):
        items = self.database_chooser.items

        struct_names = []
        for index in self.database_struct_choosed:
            struct_names.append(items[index][0])

        try:
            self.fcc.load_structs_by_names(struct_names)
            # Update currend IDB chooser to display commited structures
            # !!!!
            # No checking here, if these structuress succesfully dumped on server
            # !!!!
            for s in struct_names:
                self.cur_idb_chooser.items.append([s])

            self.RefreshField(self.curidb_chooser)
        except NetError:
            fcat_logger.logger.info('Connection with the server have been lost')


    def OnFormChange(self, fid):
        fcat_logger.logger.debug("OnFormChange() - {}".format(fid))
        if fid == self.curidb_chooser.id:
            l = self.GetControlValue(self.curidb_chooser)
            self.cur_idb_struct_choosed = l
        elif fid == self.db_chooser.id:
            l = self.GetControlValue(self.db_chooser)
            self.database_struct_choosed = l

##########################################################
#Form for functions

class FCatalogForm(Form):
    def __init__(self, fcc):
        self.fcc = fcc
        self.cur_idb_chooser = SCatalogCurrentIDBChooser("E1", fcc, self, flags=Choose2.CH_MULTI)

        # GUI will hang if no connecton to server
        # but connectino was checked in _scatalog()
        self.database_chooser = SCatalogDatabaseChooser("E2", fcc, self, flags=Choose2.CH_MULTI)
        self.hhelp = "a"*340

        self.form_code = r"""BUTTON YES NONE
BUTTON NO NONE
BUTTON CANCEL OK
HELP
ENDHELP
FCatalog


{FormChangeCb}
<Current IDB:{curidb_chooser}> <Database:{db_chooser}>
<##Commit all     :{commitAllBtn}>
<##Commit selected:{commitSelected}>
<##Import all     :{importAllBtn}>
<##Import selected:{importSelected}>
"""

        self.match = {
        'commitAllBtn':Form.ButtonInput(self.commit_all_button),
        'importAllBtn':Form.ButtonInput(self.import_all_button),
        'commitSelected':Form.ButtonInput(self.commit_selected_button),
        'importSelected':Form.ButtonInput(self.import_selected_button),
        'curidb_chooser':Form.EmbeddedChooserControl(self.cur_idb_chooser),
        'db_chooser':Form.EmbeddedChooserControl(self.database_chooser),
        'FormChangeCb': Form.FormChangeCb(self.OnFormChange)
        }

        Form.__init__(self, self.form_code, self.match)
