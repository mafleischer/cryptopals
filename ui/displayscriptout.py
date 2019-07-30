#!/usr/bin/python3
import subprocess
import npyscreen

class outPutForm(npyscreen.Form):
    def create(self):
        self.txt = self.add(npyscreen.BufferPager, name='txt')
        self.txt.set_editable(True)

    def updateTxt(self, data):
        #self.txt.values = self.txt.values + [data.decode('ascii')]
        self.txt.buffer([data.decode('ascii')], scroll_end=True)
        #self.txt.values = self.txt.values + ['sdfsdfdsf', 'aaaaaaaaaaaaaaa']
        self.txt.display()
        #time.sleep(1)

def myFunction(*args):
    f = outPutForm(name = "New Employee")
    #p = subprocess.Popen(["../set3/17-cbc-padding-oracle.py"], stdout=subprocess.PIPE, bufsize=0)
    #p = subprocess.Popen(['python3', '-u', "../set3/17-cbc-padding-oracle.py"]\
    p = subprocess.Popen(['python3', '-u', "bla.py"]\
                         ,stdout=subprocess.PIPE, bufsize=0)
    while True:
        out = p.stdout.readline()
        if out:
            f.updateTxt(out)
        else:
            break

if __name__ == '__main__':
    npyscreen.wrapper_basic(myFunction)