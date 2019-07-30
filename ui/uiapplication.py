#!/usr/bin/python3

import npyscreen
import topmenu
from manytimepadform import ManyTimePadForm

class UIApp(npyscreen.NPSAppManaged):

    def __init__(self, form):
        super().__init__()
        self.main_form = form

    def onStart(self):
        self.addForm('mtp_form', ManyTimePadForm)
        self.addForm('MAIN', self.main_form)

uiapp = UIApp(topmenu.TopMenuForm)

uiapp.run()