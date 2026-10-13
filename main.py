# -*- coding: utf-8 -*- 
from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from burp import IContextMenuFactory
from burp import IExtensionStateListener
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import LinkedList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import JFrame;
from javax.swing import JFileChooser;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from javax.swing.table import DefaultTableCellRenderer;
from javax.swing.table import DefaultTableModel;
from javax.swing.table import TableColumn;
from javax.swing.table import TableColumnModel;
from threading import Lock, Thread

###
from java.awt import Color
from java.awt.event import MouseAdapter
from javax.swing import JMenuItem
from javax.swing import JMenu
from javax.swing import JPopupMenu
from javax.swing import ListSelectionModel
from java.awt.event import ActionListener
#from java.awt.event import ListSelectionListener
from java.awt import BorderLayout
from java.awt import GridLayout
from javax.swing import JTextArea
from javax.swing import JTextField
from javax.swing import ButtonGroup
from javax.swing import JRadioButton
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import JComboBox
from javax.swing import JCheckBox
from javax.swing import JPanel
from javax.swing import SortOrder
from java.lang import Runnable
from javax.swing import RowFilter
from java.awt.event import ItemListener
from javax.swing.table import TableRowSorter
from javax.swing.event import DocumentListener
from java.util.regex import Pattern
from urlparse import *
import datetime
import time
import sched
import json
import jarray

from java.util import Base64
from java.util import Arrays
from java.util.concurrent import LinkedBlockingQueue, TimeUnit
from java.lang import System, String
from java.net import URL

RED_COLOR = Color(255,135,135) 
GREEN_COLOR = Color(107,255,127)

SHOW_ALL_BUTTON_LABEL = "Show All"
SHOW_NEW_BUTTON_LABEL = "Show New Only"
SHOW_TEST_BUTTON_LABEL = "Show Tested Only"

MONITOR_ON_LABEL = "Monitor is ON"
MONITOR_OFF_LABEL = "Monitor is OFF"

SCOPE_MONITOR_COMMENT = "RTB-History-Monitor"

TAGS = ['Login', 'Logout', 'MFA', 'PII']

# Atualiza o label de status do push na thread do Swing (thread-safe)
class PushStatusUpdater(Runnable):
    def __init__(self, ext):
        self._ext = ext

    def run(self):
        try:
            self._ext.pushStatusLabel.setText(
                "push: %d ok / %d falha / %d descartado" %
                (self._ext.PUSH_OK, self._ext.PUSH_FAIL, self._ext.PUSH_DROP))
        except:
            pass

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel, IContextMenuFactory, IExtensionStateListener):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("RTB History Monitor")

        self.GLOBAL_HANDLER_ANALYZED = False
        self.GLOBAL_HANDLER = False
        self.STATUS = True
        self.AUTOSAVE_REQUESTS = 10
        self.AUTOSAVE_TIMEOUT  = 180 # 3 minutes
        self.CONFIG_INSCOPE    = True

        self.BAD_EXTENSIONS_DEFAULT = ['.gif', '.png', '.woff', '.woff2', '.jpeg', '.jpg', '.css', '.ico', '.m3u8', '.ts']
        self.BAD_MIMES_DEFAULT      = ['gif', 'script', 'jpeg', 'jpg', 'png', 'video', 'mp2t']
        
        self.BAD_EXTENSIONS = self.BAD_EXTENSIONS_DEFAULT
        self.BAD_MIMES      = self.BAD_MIMES_DEFAULT

        # --- push para o red-burp-watchdog (independente do ON/OFF do monitor) ---
        # padrão DESLIGADO (opt-in): só ativa com PUSH_ENABLED="True" salvo
        self.PUSH_ENABLED = (self._callbacks.loadExtensionSetting("PUSH_ENABLED") == "True")
        self.PUSH_URL = self._callbacks.loadExtensionSetting("PUSH_URL") or "http://127.0.0.1:8787/ingest"
        self.PUSH_OK = 0
        self.PUSH_FAIL = 0
        self.PUSH_DROP = 0
        self._pushQueue = LinkedBlockingQueue(500)
        self._pushRun = True
        self._pushThread = Thread(target=self._pushWorker, name="rtb-watchdog-push")
        self._pushThread.start()

        # create the log and a lock on which to synchronize when adding log entries

        self._currentlyDisplayedItem = None

        self.SELECTED_MODEL_ROW = 0
        self.SELECTED_VIEW_ROW = 0

        self._log = ArrayList()
        self._fullLog = ArrayList()
        self._lock = Lock()
        self._lockFile = Lock()
        
        # main split pane
        self._parentPane = JTabbedPane()

        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        ##### config pane
        self._config = JTabbedPane()

        config = JPanel()
        iexport = JPanel()

        #config.setLayout(BorderLayout())
        config.setLayout(None)
        iexport.setLayout(None)
        
        # config radio button
        X_BASE = 40
        Y_OFFSET = 5
        Y_OPTION = 200
        Y_OPTION_SPACING = 20
        Y_CHECKMARK_SPACING = 20


        self.showAllButton = JRadioButton(SHOW_ALL_BUTTON_LABEL, True)
        self.showNewButton = JRadioButton(SHOW_NEW_BUTTON_LABEL, False)
        self.showTestedButton = JRadioButton(SHOW_TEST_BUTTON_LABEL, False)

        self.showAllButton.setBounds(40, 60 + Y_OFFSET, 400, 30)
        self.showNewButton.setBounds(40, 80 + Y_OFFSET, 400, 30)
        self.showTestedButton.setBounds(40, 100 + Y_OFFSET, 400, 30)
        #self.showNewButton = JRadioButton(SHOW_NEW_BUTTON_LABEL, False)
        #self.showTestedButton = JRadioButton(SHOW_TEST_BUTTON_LABEL, False)

        self.showAllButton.addActionListener(self.handleRadioConfig)
        self.showNewButton.addActionListener(self.handleRadioConfig)
        self.showTestedButton.addActionListener(self.handleRadioConfig) 

        self.clearButton = JButton("Clear")
        self.clearButton.addActionListener(self.handleClearButton)
        self.clearButton.setBounds(40, 20, 100, 30)

        self.startButton = JButton(MONITOR_ON_LABEL)
        self.startButton.addActionListener(self.handleStartButton)
        self.startButton.setBounds(150, 20, 200, 30)

        self.badExtensionsLabel = JLabel("Ignore extensions:")
        self.badExtensionsLabel.setBounds(X_BASE, 150, 200, 30)

        self.badExtensionsText = JTextArea("")
        self.badExtensionsText.setBounds(X_BASE, 175, 310, 30)
        self.loadBadExtensions()

        self.badExtensionsButton = JButton("Save")
        self.badExtensionsButton.addActionListener(self.handleBadExtensionsButton)
        self.badExtensionsButton.setBounds(355, 175, 70, 30)

        self.badExtensionsDefaultButton = JButton("Load Defaults")
        self.badExtensionsDefaultButton.addActionListener(self.handleBadExtensionsDefaultButton)
        self.badExtensionsDefaultButton.setBounds(430, 175, 120, 30)

        self.badMimesLabel = JLabel("Ignore mime types:")
        self.badMimesLabel.setBounds(X_BASE, 220, 200, 30)

        self.badMimesText = JTextArea("")
        self.badMimesText.setBounds(X_BASE, 245, 310, 30)
        self.loadBadMimes()

        self.badMimesButton = JButton("Save")
        self.badMimesButton.addActionListener(self.handleBadMimesButton)
        self.badMimesButton.setBounds(355, 245, 70, 30)

        self.badMimesDefaultButton = JButton("Load Defaults")
        self.badMimesDefaultButton.addActionListener(self.handleBadMimesDefaultButton)
        self.badMimesDefaultButton.setBounds(430, 245, 120, 30)


        self.otherLabel = JLabel("Other:")
        self.otherLabel.setBounds(40, 300, 120, 30)

        self.otherLabel2 = JLabel("Other:")
        self.otherLabel2.setBounds(X_BASE, Y_OPTION, 120, 30)

        self.autoSaveOption = JCheckBox("Auto save periodically")
        self.autoSaveOption.setSelected(True)
        self.autoSaveOption.addActionListener(self.handleAutoSaveOption)
        self.autoSaveOption.setBounds(X_BASE, Y_OPTION + Y_CHECKMARK_SPACING, 420, 30)

        self.repeaterOptionButton = JCheckBox("Repeater request automatically marks as analyzed")
        self.repeaterOptionButton.setSelected(True)
        self.repeaterOptionButton.addActionListener(self.handleRepeaterOptionButton)
        self.repeaterOptionButton.setBounds(50, 330, 420, 30)

        self.scopeOptionButton = JCheckBox("Follow Burp Target In Scope rules")
        self.scopeOptionButton.setSelected(True)
        self.scopeOptionButton.addActionListener(self.handleScopeOptionButton)
        self.scopeOptionButton.setBounds(50, 350, 420, 30)

        self.startOptionButton = JCheckBox("Autostart RTB History Monitor")
        self.startOptionButton.setSelected(True)
        self.startOptionButton.addActionListener(self.handleStartOption)
        self.startOptionButton.setBounds(50, 370, 420, 30)

        self.markTestedRequestsProxy = JCheckBox("Color request in Proxy tab if analyzed")
        self.markTestedRequestsProxy.setSelected(False)
        self.markTestedRequestsProxy.addActionListener(self.handleTestedRequestsProxy)
        self.markTestedRequestsProxy.setBounds(50, 390, 420, 30)

        self.markNotTestedRequestsProxy = JCheckBox("Color request in Proxy tab if NOT analyzed")
        self.markNotTestedRequestsProxy.setSelected(False)
        self.markNotTestedRequestsProxy.addActionListener(self.handleNotTestedRequestsProxy)
        self.markNotTestedRequestsProxy.setBounds(50, 410, 420, 30)

        # --- push para o red-burp-watchdog ---
        self.pushOptionButton = JCheckBox("Push request/response to Watchdog listener")
        self.pushOptionButton.setSelected(self.PUSH_ENABLED)
        self.pushOptionButton.addActionListener(self.handlePushOption)
        self.pushOptionButton.setBounds(50, 440, 420, 30)

        self.pushUrlLabel = JLabel("Listener URL:")
        self.pushUrlLabel.setBounds(50, 470, 100, 25)

        self.pushUrlText = JTextArea(self.PUSH_URL)
        self.pushUrlText.setBounds(150, 470, 310, 25)

        self.pushUrlButton = JButton("Save")
        self.pushUrlButton.addActionListener(self.handlePushUrlButton)
        self.pushUrlButton.setBounds(470, 470, 70, 25)

        self.pushStatusLabel = JLabel("push: 0 ok / 0 falha / 0 descartado")
        self.pushStatusLabel.setBounds(50, 498, 520, 25)


        self.saveButton = JButton("Save now")
        self.saveButton.addActionListener(self.handleSaveButton)
        self.saveButton.setBounds(X_BASE + 320, 95, 90, 30)

        self.loadButton = JButton("Load now")
        self.loadButton.addActionListener(self.handleLoadButton)
        self.loadButton.setBounds(X_BASE + 420, 95, 90, 30)

        self.selectPath = JButton("Select path")
        self.selectPath.addActionListener(self.selectExportFile)
        self.selectPath.setBounds(X_BASE + 530, 60, 120, 30)

        self.selectPathText = JTextArea("")
        self.selectPathText.setBounds(X_BASE, 60, 510, 30)

        self.selectPathLabel = JLabel("State file:")
        self.selectPathLabel.setBounds(X_BASE, 30, 200, 30)

        bGroup = ButtonGroup()

        bGroup.add(self.showAllButton)
        bGroup.add(self.showNewButton)
        bGroup.add(self.showTestedButton)

        config.add(self.clearButton)
        config.add(self.startButton)
        config.add(self.startOptionButton)
        config.add(self.showAllButton)
        config.add(self.showNewButton)
        config.add(self.showTestedButton)

        config.add(self.badExtensionsButton)
        config.add(self.badExtensionsText)
        config.add(self.badExtensionsLabel)

        config.add(self.badMimesButton)
        config.add(self.badMimesText)
        config.add(self.badMimesLabel)

        config.add(self.badExtensionsDefaultButton)
        config.add(self.badMimesDefaultButton)

        config.add(self.otherLabel)
        config.add(self.repeaterOptionButton)
        config.add(self.scopeOptionButton)
        config.add(self.markTestedRequestsProxy)
        config.add(self.markNotTestedRequestsProxy)
        config.add(self.pushOptionButton)
        config.add(self.pushUrlLabel)
        config.add(self.pushUrlText)
        config.add(self.pushUrlButton)
        config.add(self.pushStatusLabel)

        iexport.add(self.saveButton)
        iexport.add(self.loadButton)
        iexport.add(self.selectPath)
        iexport.add(self.selectPathText)
        iexport.add(self.selectPathLabel)
        iexport.add(self.otherLabel2)
        iexport.add(self.autoSaveOption)


        self._config.addTab("General", config)
        self._config.addTab("Import/Export", iexport)

        ##### end config pane


        # Search and coverage bar
        topBar = JPanel(BorderLayout())
        searchPanel = JPanel(BorderLayout())
        searchLabel = JLabel("  Filter: ")
        self.searchField = JTextField()
        self.searchField.getDocument().addDocumentListener(SearchDocListener(self))

        self.coverageLabel = JLabel("  Showing: 0 | Tested: 0/0 (0%)  ")

        searchPanel.add(searchLabel, BorderLayout.WEST)
        searchPanel.add(self.searchField, BorderLayout.CENTER)

        topBar.add(searchPanel, BorderLayout.CENTER)
        topBar.add(self.coverageLabel, BorderLayout.EAST)

        self._monitorPanel = JPanel(BorderLayout())
        self._monitorPanel.add(topBar, BorderLayout.NORTH)
        self._monitorPanel.add(self._splitpane, BorderLayout.CENTER)

        self._parentPane.addTab("Monitor", self._monitorPanel)
        self._parentPane.addTab("Config", self._config)
        
        # table of log entries
        self.logTable = Table(self)

        #self.logTable.setDefaultRenderer(self.logTable.getColumnClass(0), ColoredTableCellRenderer(self))

        self.logTable.setAutoCreateRowSorter(True)
        self.logTable.setRowSelectionAllowed(True)

        renderer = ColoredTableCellRenderer(self)
        #column = TableColumn(0, 190, renderer, None)

        print 'Initiating... '

        # this could be improved by fetching initial dimensions
        self.logTable.getColumn("URL").setPreferredWidth(720) # noscope
        self.logTable.getColumn("URL").setResizable(True)

        self.logTable.getColumn("Checked").setCellRenderer(renderer)
        self.logTable.getColumn("Checked").setPreferredWidth(80)
        self.logTable.getColumn("Checked").setMaxWidth(80)

        self.logTable.getColumn("Method").setPreferredWidth(120)
        #self.logTable.getColumn("Method").setMaxWidth(120)
        self.logTable.getColumn("Method").setResizable(True)

        self.logTable.getColumn("Time").setPreferredWidth(120) # noscope
        self.logTable.getColumn("Time").setResizable(True)

        self.logTable.getColumn("Tags").setPreferredWidth(200)
        self.logTable.getColumn("Tags").setResizable(True)


        scrollPane = JScrollPane(self.logTable)
        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)

        ## Row sorter shit 

        #self._tableRowSorterAutoProxyAutoAction = CustomTableRowSorter(self.logTable.getModel())
        #self.logTable.setRowSorter(self._tableRowSorterAutoProxyAutoAction)
        

        markAnalyzedButton = JMenuItem("Mark Requests as Analyzed")
        markAnalyzedButton.addActionListener(markRequestsHandler(self, True))

        markNotAnalyzedButton = JMenuItem("Mark Requests as NOT Analyzed")
        markNotAnalyzedButton.addActionListener(markRequestsHandler(self, False))

        sendRequestMenu = JMenuItem("Send Request to Repeater")
        sendRequestMenu.addActionListener(sendRequestRepeater(self))

        deleteRequestMenu = JMenuItem("Delete request")
        deleteRequestMenu.addActionListener(deleteRequestHandler(self))

        localTagsMenu = JMenu("Tags")
        for tag in TAGS:
            item = JMenuItem(tag)
            item.addActionListener(localTagHandler(self, tag))
            localTagsMenu.add(item)

        self.menu = JPopupMenu("Popup")
        self.menu.add(markAnalyzedButton)
        self.menu.add(markNotAnalyzedButton)
        self.menu.add(sendRequestMenu)
        self.menu.add(deleteRequestMenu)
        self.menu.add(localTagsMenu)

        # customize our UI components
        callbacks.customizeUiComponent(self._parentPane)
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(self._config)
        callbacks.customizeUiComponent(config)
        callbacks.customizeUiComponent(self.logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)

        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

        self.loadConfigs()

        print "Loaded!"
        self.SC = sched.scheduler(time.time, time.sleep)
        self.SCC = self.SC.enter(10, 1, self.autoSave, (self.SC,))
        self._schedulerThread = Thread(target=self.SC.run)
        self._schedulerThread.daemon = True
        self._schedulerThread.start()

        return
        
    ##### CUSTOM CODE #####
    def loadConfigs(self):

        if self._callbacks.loadExtensionSetting("CONFIG_AUTOSTART") == "False":
            self.startOptionButton.setSelected(False)
            self.startOrStop(None, False)
        else:
            self.startOptionButton.setSelected(True)
            self.startOrStop(None, True)

        if self._callbacks.loadExtensionSetting("exportFile") != "" and self._callbacks.loadExtensionSetting("exportFile") is not None:
            self.selectPathText.setText(self._callbacks.loadExtensionSetting("exportFile"))

        if self._callbacks.loadExtensionSetting("CONFIG_REPEATER") == "False":
            self.repeaterOptionButton.setSelected(False)
        else:
            self.repeaterOptionButton.setSelected(True)

        if self._callbacks.loadExtensionSetting("CONFIG_INSCOPE") == "False":
            self.scopeOptionButton.setSelected(False)
        else:
            self.scopeOptionButton.setSelected(True)

        if self._callbacks.loadExtensionSetting("CONFIG_AUTOSAVE") == "False":
            self.autoSaveOption.setSelected(False)
        else:
            self.autoSaveOption.setSelected(True)
        
        if self._callbacks.loadExtensionSetting("CONFIG_HIGHLIGHT_TESTED") == "True":
            self.markTestedRequestsProxy.setSelected(True)
        else:
            self.markTestedRequestsProxy.setSelected(False)

        if self._callbacks.loadExtensionSetting("CONFIG_HIGHLIGHT_NOT_TESTED") == "True":
            self.markNotTestedRequestsProxy.setSelected(True)
        else:
            self.markNotTestedRequestsProxy.setSelected(False)





        return

    def selectExportFile(self, event):
        parentFrame = JFrame()
        fileChooser = JFileChooser()
        fileChooser.setDialogTitle("Specify file to save state")
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY)

        userSelection = fileChooser.showOpenDialog(parentFrame)

        if (userSelection == JFileChooser.APPROVE_OPTION):
            fileLoad = fileChooser.getSelectedFile()
            filename = fileLoad.getAbsolutePath()

            self.selectPathText.setText(filename)
            print 'Filename selected:' + filename
            self._callbacks.saveExtensionSetting("exportFile", filename)

        return


    def extensionUnloaded(self):
        print 'extension unloading.. '

        print 'stopping push worker.. '
        self._pushRun = False

        print 'canceling scheduler.. '
        map(self.SC.cancel, self.SC.queue)
        return

    def loadBadExtensions(self):
        bad = self._callbacks.loadExtensionSetting("badExtensions")
        if bad:
            self.badExtensionsText.setText(bad)
            # transform text to array 
            bad = bad.replace(" ", "")
            self.BAD_EXTENSIONS = bad.split(",")
        else:
            print 'no bad extension saved, reverting'
            self.badExtensionsText.setText(", ".join(self.BAD_EXTENSIONS))

    def loadBadMimes(self):
        bad = self._callbacks.loadExtensionSetting("badMimes")
        if bad:
            self.badMimesText.setText(bad)

            bad = bad.replace(" ", "")
            self.BAD_MIMES = bad.split(",")
        else:
            print 'no bad mimes saved, reverting'
            self.badMimesText.setText(", ".join(self.BAD_MIMES))



        

    ## GLOBAL CONTEXT CODE ##

    def createMenuItems(self, invocation):
        responses = invocation.getSelectedMessages()
        if responses > 0:
            ret = LinkedList()
            analyzedMenuItem = JMenuItem("Mark as analyzed")
            notAnalyzedMenuItem = JMenuItem("Mark as NOT analyzed")

            tagsMenu = JMenu("Tags")
            for tag in TAGS:
                tagItem = JMenuItem(tag)
                for response in responses:
                    tagItem.addActionListener(handleTagMenuItems(self, response, tag))
                tagsMenu.add(tagItem)

            for response in responses:
                analyzedMenuItem.addActionListener(handleMenuItems(self, response, "analyzed"))
                notAnalyzedMenuItem.addActionListener(handleMenuItems(self, response, "not"))

            ret.add(analyzedMenuItem)
            ret.add(notAnalyzedMenuItem)
            ret.add(tagsMenu)
            return ret


    def getEndpoint(self, requestResponse):
        url_ = str(self._helpers.analyzeRequest(requestResponse).getUrl())
        o = urlparse(url_)

        url = o.scheme+"://"+o.netloc+o.path
        #print "Url3: " + url
        return url


    def getMethod(self, requestResponse):
        return self._helpers.analyzeRequest(requestResponse).getMethod()


    ##### CUSTOM CODE #####
    def handleTestedRequestsProxy(self, event):
        self._callbacks.saveExtensionSetting("CONFIG_HIGHLIGHT_TESTED", str(self.markTestedRequestsProxy.isSelected()))
        return

    def handleNotTestedRequestsProxy(self, event):
        self._callbacks.saveExtensionSetting("CONFIG_HIGHLIGHT_NOT_TESTED", str(self.markNotTestedRequestsProxy.isSelected()))
        return



    def handleStartOption(self, event):
        self._callbacks.saveExtensionSetting("CONFIG_AUTOSTART", str(self.startOptionButton.isSelected()))
        #print 'saving autostart: ' + str(self.startOptionButton.isSelected())
        return

    def startOrStop(self, event, autoStart):
        if (self.startButton.getText() == MONITOR_OFF_LABEL) or autoStart:
            self.startButton.setText(MONITOR_ON_LABEL)
            self.startButton.setBackground(GREEN_COLOR)
            self.STATUS = True
        else:
            self.startButton.setText(MONITOR_OFF_LABEL)
            self.startButton.setBackground(RED_COLOR)
            self.STATUS = False

    def handleStartButton(self, event):
        self.startOrStop(event, False)

    def handleAutoSaveOption(self, event):
        self._callbacks.saveExtensionSetting("CONFIG_AUTOSAVE", str(self.autoSaveOption.isSelected()))
        return

    def handleSaveButton(self, event):
        self.exportState("test")

    def handleLoadButton(self, event):
        self.importState("test")

    def handleRepeaterOptionButton(self, event):
        self._callbacks.saveExtensionSetting("CONFIG_REPEATER", str(self.repeaterOptionButton.isSelected()))
        return

    def handleScopeOptionButton(self, event):
        self.CONFIG_INSCOPE = self.scopeOptionButton.isSelected()
        self._callbacks.saveExtensionSetting("CONFIG_INSCOPE", str(self.CONFIG_INSCOPE))
        return

    def handlePushOption(self, event):
        self.PUSH_ENABLED = self.pushOptionButton.isSelected()
        self._callbacks.saveExtensionSetting("PUSH_ENABLED", str(self.PUSH_ENABLED))
        return

    def handlePushUrlButton(self, event):
        self.PUSH_URL = self.pushUrlText.getText().strip()
        self._callbacks.saveExtensionSetting("PUSH_URL", self.PUSH_URL)
        return

    def handleBadExtensionsButton(self, event):
        #print "before BAD array: "
        print self.BAD_EXTENSIONS

        extensions = self.badExtensionsText.getText()
        self._callbacks.saveExtensionSetting("badExtensions", extensions)
        print 'New extensions blocked: ' + extensions 
        bad = extensions.replace(" ", "")
        self.BAD_EXTENSIONS = bad.split(",")
        #print "BAD array: "
        #print self.BAD_EXTENSIONS

    def handleBadExtensionsDefaultButton(self, event):
        self.BAD_EXTENSIONS = self.BAD_EXTENSIONS_DEFAULT
        self.badExtensionsText.setText(", ".join(self.BAD_EXTENSIONS))
        self._callbacks.saveExtensionSetting("badExtensions", ", ".join(self.BAD_EXTENSIONS))
        return

    def handleBadMimesDefaultButton(self, event):
        self.BAD_MIMES = self.BAD_MIMES_DEFAULT
        self.badMimesText.setText(", ".join(self.BAD_MIMES))
        self._callbacks.saveExtensionSetting("badMimes", ", ".join(self.BAD_MIMES))
        return

    def handleBadMimesButton(self, event):
        mimes = self.badMimesText.getText()
        self._callbacks.saveExtensionSetting("badMimes", mimes)
        print 'New mimes blocked: ' + mimes 
        bad = mimes.replace(" ", "")
        self.BAD_MIMES = bad.split(",")

    def handleClearButton(self, event):
        print 'Clearing table'
        self._lock.acquire()
        self._log = ArrayList()
        self._fullLog = ArrayList()
        self._lock.release()
        return

    def handleRadioConfig(self, event):
        #print ' radio button clicked '
        #print event.getActionCommand()
        self._lock.acquire()

        if event.getActionCommand() == SHOW_ALL_BUTTON_LABEL:
            print "Showing all"
            self._log = self._fullLog
        elif event.getActionCommand() == SHOW_NEW_BUTTON_LABEL:
            print "Showing new scope only"
            tmpLog = ArrayList()
            for item in self._fullLog:
                if not(item._analyzed):
                    tmpLog.add(item)
            self._log = tmpLog
        elif event.getActionCommand() == SHOW_TEST_BUTTON_LABEL:
            print "Showing tested scope only"
            tmpLog = ArrayList()
            for item in self._fullLog:
                if item._analyzed:
                    tmpLog.add(item)
            self._log = tmpLog
        else:
            print "unrecognized radio label"

        
        self.fireTableDataChanged()
        #self._tableRowSorterAutoProxyAutoAction.toggleSortOrder(1)
        #self.toggleSortOrder(2)
        
        #self.logTable.toggleSortOrder(2)

        # refresh table?

        self._lock.release()


    #
    # implement ITab
    #
    
    def getTabCaption(self):
        return "RTB History Monitor"
    
    def getUiComponent(self):
        return self._parentPane
        
    #
    # implement IHttpListener
    #
    
    def markAnalyzed(self, messageIsRequest, state):
        #print "markAnalyzed..."
        self._lock.acquire()

        url = self.getEndpoint(messageIsRequest)
        for item in self._log:
            if url == item._url:
                item._analyzed = state
                self._lock.release()
                return
        self._lock.release()
        return

    # ------------------------------------------------------------------
    # Push para o red-burp-watchdog — tempo real, sem corte de 5KB.
    # Politica de tamanho: completo <=512KB; truncado (headers + inicio do
    # corpo) ate 2MB; acima de 2MB descarta (protege o heap do Burp).
    # ------------------------------------------------------------------
    PUSH_TOOLS = ("Proxy", "Repeater", "Target")
    PUSH_FULL_LIMIT = 524288      # 512KB
    PUSH_HARD_LIMIT = 2097152     # 2MB

    def _watchdogPush(self, toolFlag, messageInfo):
        try:
            tool = self._callbacks.getToolName(toolFlag)
            if tool not in self.PUSH_TOOLS:
                return
            req = messageInfo.getRequest()
            if req is None:
                return
            url = self._helpers.analyzeRequest(messageInfo).getUrl()
            if not self._callbacks.isInScope(url):
                return
            path = str(url.getPath())
            for extension in self.BAD_EXTENSIONS:
                if path.endswith(extension):
                    return
            resp = messageInfo.getResponse()
            if resp is not None:
                mime = self._helpers.analyzeResponse(resp).getStatedMimeType()
                if mime and mime.lower() in self.BAD_MIMES:
                    return
            reqLen = len(req)
            respLen = len(resp) if resp is not None else 0
            if reqLen > self.PUSH_HARD_LIMIT or respLen > self.PUSH_HARD_LIMIT:
                self.PUSH_DROP += 1
                self._updatePushStatus()
                return
            respTrunc = False
            if resp is not None and respLen > self.PUSH_FULL_LIMIT:
                resp = self._truncateKeepHeaders(resp, self.PUSH_FULL_LIMIT)
                respTrunc = True
            payload = {
                "ts": datetime.datetime.fromtimestamp(time.time()).isoformat(),
                "tool": tool,
                "request_b64": Base64.getEncoder().encodeToString(req),
                "response_b64": (Base64.getEncoder().encodeToString(resp) if resp is not None else ""),
                "resp_truncated": respTrunc,
            }
            if not self._pushQueue.offer(json.dumps(payload)):
                self.PUSH_DROP += 1
                self._updatePushStatus()
        except:
            pass  # o push nunca pode afetar o monitor/proxy

    def _truncateKeepHeaders(self, arr, limit):
        # mantem headers completos + inicio do corpo ate <limit> bytes
        try:
            n = len(arr)
            if n <= limit:
                return arr
            scan = min(n, 65536)
            hdrEnd = -1
            i = 0
            while i < scan - 3:
                if arr[i] == 13 and arr[i+1] == 10 and arr[i+2] == 13 and arr[i+3] == 10:
                    hdrEnd = i + 4
                    break
                i += 1
            if hdrEnd < 0 or hdrEnd >= limit:
                return Arrays.copyOfRange(arr, 0, limit)
            bodyLen = limit - hdrEnd
            out = jarray.zeros(limit, 'b')
            System.arraycopy(arr, 0, out, 0, hdrEnd)
            System.arraycopy(arr, hdrEnd, out, hdrEnd, bodyLen)
            return out
        except:
            return arr

    def _pushWorker(self):
        while self._pushRun:
            try:
                body = self._pushQueue.poll(1, TimeUnit.SECONDS)
            except:
                continue
            if body is None:
                continue
            try:
                conn = URL(self.PUSH_URL).openConnection()
                conn.setRequestMethod("POST")
                conn.setConnectTimeout(1000)
                conn.setReadTimeout(3000)
                conn.setDoOutput(True)
                conn.setRequestProperty("Content-Type", "application/json")
                data = String(body).getBytes("UTF-8")
                conn.setFixedLengthStreamingMode(len(data))
                out = conn.getOutputStream()
                out.write(data)
                out.flush()
                out.close()
                code = conn.getResponseCode()
                try:
                    conn.getInputStream().close()
                except:
                    pass
                if code == 200:
                    self.PUSH_OK += 1
                else:
                    self.PUSH_FAIL += 1
            except:
                self.PUSH_FAIL += 1
            self._updatePushStatus()

    def _updatePushStatus(self):
        try:
            SwingUtilities.invokeLater(PushStatusUpdater(self))
        except:
            pass

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # push watchdog: independente do ON/OFF do monitor; apenas na fase de resposta
        try:
            if (not messageIsRequest) and self.PUSH_ENABLED:
                self._watchdogPush(toolFlag, messageInfo)
        except:
            pass

        # only process requests

        #print "processing httpMessage.."
        #print messageIsRequest
        #print "processHttp status: " + str(self.STATUS)
        if not(self.STATUS):
            return

        #print "global handler status: (true): " + str(self.GLOBAL_HANDLER)
        #print "(processHTTP) messageIsRequest"
        #print messageIsRequest 
        if messageIsRequest and not(self.GLOBAL_HANDLER):
            return

        if self.scopeOptionButton.isSelected():
            url = self._helpers.analyzeRequest(messageInfo).getUrl()
            if not self._callbacks.isInScope(url):
                #print 'Url not in scope, skipping.. '
                return

        #print "still processing httpMessage.., request came from: " + self._callbacks.getToolName(toolFlag)

        if ((self._callbacks.getToolName(toolFlag) != "Repeater") and (self._callbacks.getToolName(toolFlag) != "Proxy") and (self._callbacks.getToolName(toolFlag) != "Target")):
            #print 'Aborting processHTTP, request came from: ' + str(self._callbacks.getToolName(toolFlag))
            return


        url = self.getEndpoint(messageInfo)
        method = self.getMethod(messageInfo)

        #print "(processHTTP) before extensions check: " + url 

        for extension in self.BAD_EXTENSIONS:
            if url.endswith(extension):
                return

        if messageInfo.getResponse():
            mime = self._helpers.analyzeResponse(messageInfo.getResponse()).getStatedMimeType()
            #print 'Declared mime:' + mime
            mime = mime.lower()
            if mime in self.BAD_MIMES:
                #print 'Bad mime:' + mime
                return

        #print "[httpMessage] before lock"        
        # create a new log entry with the message details
        self._lock.acquire()
        row = self._log.size()


        for item in self._log:
            if url == item._url:
                if method == self._helpers.analyzeRequest(item._requestResponse).getMethod():
                    #print 'duplicate URL+method, skipping.. '
                    self._lock.release()

                    # has it been analyzed?
                    analyzed = False
                    if self._callbacks.getToolName(toolFlag) == "Repeater":
                        if self.repeaterOptionButton.isSelected():
                            analyzed = True
                            #print "[httpMessage] setting analyzed as true" 
                    if self.GLOBAL_HANDLER_ANALYZED:
                        analyzed = True

                    item._analyzed = analyzed
                    self.paintItems(messageInfo, item)

                    return

        #print "[httpMessage] before setComment" 
        messageInfo.setComment(SCOPE_MONITOR_COMMENT)
        # reached here, must be new entry
        analyzed = False
        if self._callbacks.getToolName(toolFlag) == "Repeater":
            if self.repeaterOptionButton.isSelected():
                analyzed = True
                #print "[httpMessage] setting analyzed as true" 
        if self.GLOBAL_HANDLER_ANALYZED:
            analyzed = True

        #print "[httpMessage] after comment" 
        #print 'in httpmessage, response:'
        #print self._helpers.analyzeResponse(messageInfo.getResponse())

        date = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
        entry = LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), url, analyzed, date, method)
        #print "toolFlag: " + str(toolFlag)

        #print "(processHTTP) Adding URL: " + url 
        self._log.add(entry)
        self._fullLog.add(entry)
        self.fireTableRowsInserted(row, row)

        self.paintItems(messageInfo, entry)

        self._lock.release()

        #print "columnCoun:" + str(self.logTable.getColumnCount())

    #
    # extend AbstractTableModel
    #
    
    def paintItems(self, messageInfo, item):
        '''
        print "in paint Items"
        print "mark color is: (true)" + str(self.markTestedRequestsProxy.isSelected())
        print "global handler analyzed:           :" + str(self.GLOBAL_HANDLER_ANALYZED)
        print "item analyzed should be the same ^^:" + str(item._analyzed)
        '''
        if (self.markTestedRequestsProxy.isSelected()) and (item._analyzed and self.GLOBAL_HANDLER_ANALYZED):
            messageInfo.setHighlight("green")
            return

        if self.markNotTestedRequestsProxy.isSelected() and not(item._analyzed):
            messageInfo.setHighlight("red")


    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 5

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Checked"
        if columnIndex == 1:
            return "URL"
        if columnIndex == 2:
            return "Method"
        if columnIndex == 3:
            return "Time"
        if columnIndex == 4:
            return "Tags"

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)

        #self.setBackground(Color.GREEN)
        return self.returnEntry(rowIndex, columnIndex, logEntry)

        if self.showNewButton.isSelected() and not(logEntry._analyzed):  
            return self.returnEntry(rowIndex, columnIndex, logEntry)
        elif self.showTestedButton.isSelected() and logEntry._analyzed:
            return self.returnEntry(rowIndex, columnIndex, logEntry)
        elif self.showAllButton.isSelected():
            return self.returnEntry(rowIndex, columnIndex, logEntry)


    def returnEntry(self, rowIndex, columnIndex, entry):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            if logEntry._analyzed:
                return "True"
            else:
                return "False"
        if columnIndex == 1:
            return self._helpers.urlDecode(logEntry._url) 
        if columnIndex == 2:
            return logEntry._method
        if columnIndex == 3:
            return logEntry._date
        if columnIndex == 4:
            return logEntry._tags
        return ""

    def isCellEditable(self, rowIndex, columnIndex):
        return columnIndex == 4

    def setValueAt(self, value, rowIndex, columnIndex):
        if columnIndex == 4:
            logEntry = self._log.get(rowIndex)
            logEntry._tags = value if value else ""
            self.fireTableCellUpdated(rowIndex, columnIndex)


    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        #print 'getRequest called'
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        #print 'getResponse called: '
        print self._currentlyDisplayedItem.getResponse()
        return self._currentlyDisplayedItem.getResponse()
    

    def exportRequest(self, entity, filename):

        line = str(entity._analyzed) + ","
        line = line + self._helpers.urlEncode(entity._url).replace(",", "%2c") + ","    # URL is encoded so we should be good
        line = line + entity._method  + ","
        line = line + entity._date + ","
        line = line + entity._tags.replace(",", "%2c")
        line = line + '\n'

        #print 'Exporting: "' + line + '"'
        return line

    def exportUrlEncode(self, url):
        return self._helpers.urlEncode(url).replace(",", "%2c")

    def exportState(self, filename):
        filename = self.selectPathText.getText()

        if filename == "":
            filename = self._callbacks.loadExtensionSetting("exportFile")
            print 'Empty filename, skipping export'
            return 
        else:
            self._callbacks.saveExtensionSetting("exportFile", filename)

        print 'saving state to: ' + filename

        savedUrls = []
        
        self._lockFile.acquire()
        try:
            with open(filename, 'r') as fr:
                savedEntries = fr.read().splitlines()
                savedUrls = []
                for savedEntry in savedEntries:
                    savedUrls.append(savedEntry.split(",")[1])
                #print "savedUrls len: " + str(len(savedUrls))
                #print "savedUrls:"
                #print savedUrls
                fr.close()
        except IOError:
            print "Autosaving skipped as file doesn't exist yet" 

        with open(filename, 'a+') as f:
            
            for item in self._log:
                if self.exportUrlEncode(item._url) not in savedUrls:
                    line = self.exportRequest(item, "xx")
                    f.write(line)
            f.close()
        self._lockFile.release()
        
        return

    def importState(self, filename):
        filename = self.selectPathText.getText()

        if filename == "":
            filename = self._callbacks.loadExtensionSetting("exportFile")
            print 'Empty filename, skipping import'
            return 
        else:
            self._callbacks.saveExtensionSetting("exportFile", filename)

        print 'loading state from: ' + filename

        self.STATUS = False

        self._lockFile.acquire()
        with open(filename, 'r') as f:

            proxy = self._callbacks.getProxyHistory()

            proxyItems = []
            for item in proxy:
                if item.getComment():
                    if SCOPE_MONITOR_COMMENT in item.getComment():
                        proxyItems.append(item)

            #print 'proxyItems has: ' + str(len(proxyItems))
            # TODO - if no proxy items, sraight to import

            lines = f.read().splitlines()
            for line in lines:
                data = line.split(",")
                url = data[1]
                url = self._helpers.urlDecode(url) 

                #print 'Saving: ' + url

                analyzed = False
                if data[0] == "True":
                    analyzed = True

                requestResponse = None
                for request in proxyItems:
                    if url == self.getEndpoint(request):
                        #print 'Match found when importing for url: ' + url
                        requestResponse = request
                        break

                tags = data[4].replace("%2c", ",") if len(data) > 4 else ""
                self._log.add(LogEntry("", requestResponse, url, analyzed, data[3], data[2], tags) )

                #(self, tool, requestResponse, url, analyzed, date, method, tags):

            self._lockFile.release()
        print 'finished loading.. '
        #print 'size: ' + str(self._log.size())
        self.fireTableDataChanged()

        if self.startButton.getText() == MONITOR_ON_LABEL:
            self.STATUS = True

        return

    def autoSave(self, sc):
        #print 'autosaving.. lol what'
        if self.autoSaveOption.isSelected():
            print "[" + self.getTime() + "] autosaving to " + self._callbacks.loadExtensionSetting("exportFile")
            self.exportState("")

        self.SC.enter(self.AUTOSAVE_TIMEOUT, 1, self.autoSave, (self.SC,))
        return

    def getTime(self):
        date = datetime.datetime.fromtimestamp(time.time()).strftime('%H:%M:%S')
        return date

    def updateCoverage(self):
        try:
            total = self._fullLog.size()
            tested = 0
            for item in self._fullLog:
                if item._analyzed:
                    tested += 1

            showing = self.logTable.getRowCount()

            if total > 0:
                pct = int(100.0 * tested / total)
            else:
                pct = 0

            text = "  Showing: %d | Tested: %d/%d (%d%%)  " % (showing, tested, total, pct)
            self.coverageLabel.setText(text)
        except:
            pass

    def applySearchFilter(self):
        text = self.searchField.getText()
        sorter = self.logTable.getRowSorter()
        if sorter is None:
            return
        if text and text.strip():
            try:
                sorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(text.strip())))
            except:
                pass
        else:
            sorter.setRowFilter(None)
        self.updateCoverage()

    def fireTableDataChanged(self):
        AbstractTableModel.fireTableDataChanged(self)
        self.updateCoverage()

    def fireTableRowsInserted(self, firstRow, lastRow):
        AbstractTableModel.fireTableRowsInserted(self, firstRow, lastRow)
        self.updateCoverage()

#
# extend JTable to handle cell selection
#

    #def getRequest(self,):
    
class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        self.addMouseListener(mouseclick(self._extender))
        self.setRowSelectionAllowed(True)
        self.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
    
    def changeSelection(self, row, col, toggle, extend):
    
        # shows "entries" matching

        # show the log entry for the selected row
        #print 'Selecting entry ' + str(row) + ' in changeSelection: ' 

        JTable.changeSelection(self, row, col, toggle, extend)

        modelRow = self.convertRowIndexToModel(row)
        #print 'converted: ' + str()

        logEntry = self._extender._log.get(modelRow)

        #print str(self._extender._helpers.analyzeRequest(logEntry._requestResponse).getUrl())

        self._extender.SELECTED_MODEL_ROW = modelRow
        self._extender.SELECTED_VIEW_ROW = row

        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        
        
        #JTable.changeSelection(self, row, col, toggle, extend)
        return

    
class mouseclick(MouseAdapter):
    def __init__(self, extender):
        self._extender = extender

    def mousePressed(self, evt):
        if evt.button == 3:
            row = self._extender.logTable.rowAtPoint(evt.getPoint())
            if row >= 0 and not self._extender.logTable.isRowSelected(row):
                self._extender.logTable.setRowSelectionInterval(row, row)

    def mouseReleased(self, evt):
        if evt.button == 3:
            self._extender.menu.show(evt.getComponent(), evt.getX(), evt.getY())


class ColoredTableCellRenderer(DefaultTableCellRenderer):
    def __init__(self, extender):
        self._extender = extender

    def setValue(self, value):
        if value == "False":
            self.setBackground(Color(255,135,135))
            #self.setForeground(Color.RED)
        elif value == "True":
            self.setBackground(Color(107,255,127))
            #self.setForeground(Color.GREEN)
        #return value
        self.super__setValue(value)


#
# class to hold details of each log entry
#

class LogEntry:
    def __init__(self, tool, requestResponse, url, analyzed, date, method, tags=""):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url
        self._displayed = False
        self._analyzed  = analyzed
        self._date = date 
        self._method = method
        self._tags = tags

class CustomTableRowSorter(TableRowSorter):

    # override toggleSortOrder method
    def toggleSortOrder(self, column):

        # check if valid column 
        if column >= 0:

            # get the sort keys
            keys = self.getSortKeys()

            # check if the sort keys are not empty
            if keys.isEmpty() == False:

                # get the sort key
                sortKey = keys.get(0)

                # check if the column clicked is sorted in descending order
                if sortKey.getColumn() == column and sortKey.getSortOrder() == SortOrder.DESCENDING:

                    # clear sorting
                    self.setSortKeys(None)

                    # do not continue
                    return

        # try to toggle default toggleSortOrder
        try:
            # toggle default toggleSortOrder
            TableRowSorter.toggleSortOrder(self, column)

        # catch if table is being sorted by processProxyMessage and user
        except:
            pass

class deleteRequestHandler(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, e):
        rows = self._extender.logTable.getSelectedRows()

        # Convert view indices to model indices and sort descending
        # to avoid index shift when removing items
        model_rows = sorted(
            [self._extender.logTable.convertRowIndexToModel(row) for row in rows],
            reverse=True
        )

        self._extender._lock.acquire()
        for model_row in model_rows:
            entry = self._extender._log.get(model_row)
            self._extender._log.remove(entry)
            self._extender._fullLog.remove(entry)
        self._extender._lock.release()

        self._extender.fireTableDataChanged()

        return 

class sendRequestRepeater(ActionListener):
    def __init__(self, extender):
        self._extender = extender

    def actionPerformed(self, e):
        #print "COPY SELECTED URL HANDLER ******"

        rows = self._extender.logTable.getSelectedRows()
        for row in rows:

            model_row = self._extender.logTable.convertRowIndexToModel(row)

            request = self._extender._log.get(model_row)._requestResponse
            url = self._extender._log.get(model_row)._url

            host = request.getHttpService().getHost()
            port = request.getHttpService().getPort()
            proto = request.getHttpService().getProtocol()

            secure = True if proto == 'https' else False
            
            self._extender._callbacks.sendToRepeater(host, port, secure, request.getRequest(), None);

        return 

### LOCAL CONTEXT
class markRequestsHandler(ActionListener):
    def __init__(self, extender, state):
        self._extender = extender
        self._state = state

    def actionPerformed(self, e):
        #print "COPY SELECTED URL HANDLER ******"
        #print "Status is: " + str(self._state)

        rows = self._extender.logTable.getSelectedRows()
        for row in rows:

            model_row = self._extender.logTable.convertRowIndexToModel(row)
            url = self._extender._log.get(model_row)._url

            #print "Changing url: " + url

            ### TODO REPLACE FOR MARK_AS_ANALYZED 
            self._extender._lock.acquire()

            for item in self._extender._log:
                if url == item._url:
                    item._analyzed = self._state
                    self._extender.paintItems(item._requestResponse, item)
                    #break
            self._extender._lock.release()


        self._extender.fireTableDataChanged()
        #print 'refreshing view ..... *****'

        #self._extender.changeSelection(self._extender.SELECTED_VIEW_ROW, 1, True, True)
        #self._extender.changeSelection(self._extender.SELECTED_VIEW_ROW, 1, False, False)
        #self._extender.changeSelection(self._extender.SELECTED_VIEW_ROW, 1, True, True)

        return 


### GLOBAL CONTEXT #### 
class handleMenuItems(ActionListener):
    def __init__(self, extender, messageInfo, menuName):
        self._extender = extender
        self._menuName = menuName
        self._messageInfo = messageInfo

    def actionPerformed(self, e):
        self._extender.GLOBAL_HANDLER = True

        if self._menuName == "analyzed":
            self._extender.GLOBAL_HANDLER_ANALYZED = True
            self._extender.processHttpMessage(4, self._messageInfo, self._messageInfo)
            self._extender.markAnalyzed(self._messageInfo, True)
            #start_new_thread(self._extender.sendRequestToAutorizeWork,(self._messageInfo,))

        if self._menuName == "not":
            self._extender.GLOBAL_HANDLER_ANALYZED = False
            self._extender.processHttpMessage(4, self._messageInfo, self._messageInfo)
            self._extender.markAnalyzed(self._messageInfo, False)

        self._extender.GLOBAL_HANDLER_ANALYZED = False
        self._extender.GLOBAL_HANDLER = False
            #self._extender.replaceString.setText(self._extender.getCookieFromMessage(self._messageInfo))


### GLOBAL TAG CONTEXT ###
class handleTagMenuItems(ActionListener):
    def __init__(self, extender, messageInfo, tag):
        self._extender = extender
        self._messageInfo = messageInfo
        self._tag = tag

    def actionPerformed(self, e):
        url = self._extender.getEndpoint(self._messageInfo)
        self._extender._lock.acquire()
        found = False
        for item in self._extender._fullLog:
            if url == item._url:
                existing = item._tags.split("|") if item._tags else []
                if self._tag not in existing:
                    existing.append(self._tag)
                item._tags = "|".join(existing)
                found = True
                break
        self._extender._lock.release()
        if found:
            SwingUtilities.invokeLater(lambda: self._extender.fireTableDataChanged())
        else:
            print "[Tags] URL not found in log: " + url


### LOCAL TAG CONTEXT ###
class localTagHandler(ActionListener):
    def __init__(self, extender, tag):
        self._extender = extender
        self._tag = tag

    def actionPerformed(self, e):
        rows = self._extender.logTable.getSelectedRows()
        for row in rows:
            model_row = self._extender.logTable.convertRowIndexToModel(row)
            url = self._extender._log.get(model_row)._url

            self._extender._lock.acquire()
            for item in self._extender._log:
                if url == item._url:
                    existing = item._tags.split("|") if item._tags else []
                    if self._tag not in existing:
                        existing.append(self._tag)
                    item._tags = "|".join(existing)
                    break
            self._extender._lock.release()

        SwingUtilities.invokeLater(lambda: self._extender.fireTableDataChanged())


class SearchDocListener(DocumentListener):
    def __init__(self, extender):
        self._extender = extender

    def insertUpdate(self, e):
        self._extender.applySearchFilter()

    def removeUpdate(self, e):
        self._extender.applySearchFilter()

    def changedUpdate(self, e):
        self._extender.applySearchFilter()
