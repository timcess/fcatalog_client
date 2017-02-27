import threading

from fcatalog_client.qt_backend import QT_BACKEND_PYQT5, QT_BACKEND_PYSIDE

try:
    from PyQt5.QtCore import pyqtSignal as Signal, QObject, QThread
    QT_BACKEND = QT_BACKEND_PYQT5
except:
    from PySide.QtCore import Signal, QObject, QThread
    QT_BACKEND = QT_BACKEND_PYSIDE

class ThreadExecutorError(Exception): pass

# Thread executor. Can run only one thread at a time.
class ThreadExecutor(object):
    def __init__(self):
        # Currently not running:
        self._is_running = False

    def execute(self,func,*args,**kwargs):
        """
        Execute function in a new thread.
        Returns a handle to the created thread.
        """
        if self._is_running:
            raise ThreadExecutorError('Already running!')

        self._is_running = True

        def worker():
            # Run the function:
            try:
                func(*args,**kwargs)
            finally:
                # Mark finished running when the execution
                # of the function is done.
                self._is_running = False

        # Run the worker in a new thread:
        t = threading.Thread(target=worker)
        t.start()

        return t

    def is_running(self):
        return self._is_running

    def jjoin(self):
        while self.is_running:
            pass

class TerminatingSignal(QObject):
    sig = Signal()

class QThr(QThread):
    def run(self):
        print("simple!")

    def callback_on_termination(self, term_func):
        self.term_sig.sig.connect(term_func)
