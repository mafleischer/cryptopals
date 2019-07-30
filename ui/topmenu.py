#!/usr/bin/python3

import npyscreen
import curses

from manytimepadform import ManyTimePadForm

class TopMenuForm(npyscreen.FormWithMenus):
    def create(self):
        self.how_exited_handers[npyscreen.wgwidget.EXITED_ESCAPE] = self.exit_application

        # The menus are created here.
        self.menu_main = self.add_menu(name="Main Menu", shortcut="^M")

        self.menu_run_challenge = self.menu_main.addNewSubmenu("Run Challenge Script...", "^R")
        self.menu_run_challenge.addItem(text="Just dummy right now",\
                                        onSelect=self.dummy)
        self.menu_main.addItem(text="Many Time Pad",\
                               onSelect=self.load_many_time_pad, shortcut="^M")
        self.menu_main.addItem(text="Exit", onSelect=self.exit_application, shortcut="^E")

    def dummy(self):
        npyscreen.notify_confirm('Just dummy right now')

    def load_many_time_pad(self):
        self.parentApp.setNextForm('mtp_form')
        self.parentApp.switchFormNow()

    def exit_application(self):
        self.parentApp.setNextForm(None)
        self.editing = False
        self.parentApp.switchFormNow()