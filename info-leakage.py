from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab
from array import array
import json
import java.awt as awt
from javax.swing import JPanel, JScrollPane, JTextArea, JButton, JFileChooser, JLabel, JTabbedPane, JOptionPane

VERSION = "1.0.5"
# Replace GREP_STRINGS with an empty list to be populated via the UI
GREP_STRINGS = []

class BurpExtender(IBurpExtender, IScannerCheck, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Info Leakage - " + VERSION)
        callbacks.registerScannerCheck(self)

        self._initUI()
        callbacks.customizeUiComponent(self._main_panel)
        callbacks.addSuiteTab(self)
        self.grep_strings_list = []
        self._load_grep_strings()

        print("Info Leakage - version {} loaded successfully".format(VERSION))

    def _get_matches(self, response, match):
        matches = []
        start = 0
        reslen = len(response)
        matchlen = len(match)
        while start < reslen:
            start = self._helpers.indexOf(response, match, True, start, reslen)
            if start == -1:
                break
            matches.append(array('i', [start, start + matchlen]))
            start += matchlen

        return matches

    def doPassiveScan(self, baseRequestResponse):
        issues = []
        for grep_string in self.grep_strings_list:
            matches = self._get_matches(baseRequestResponse.getResponse(), bytearray(grep_string, 'utf-8'))
            if (len(matches) > 0):
                print("Match found for string:", grep_string)
                issue = CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, matches)],
                    "Info Leakage",
                    "The response contains the string: " + grep_string,
                    "High"
                )
                issues.append(issue)

        return issues if issues else None
    
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        pass

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName() and existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1

        return 0

    def _initUI(self):
        self._main_panel = JPanel()
        tabbedPane = JTabbedPane()

        # Settings tab
        settings_panel = JPanel()
        settings_panel.setLayout(awt.GridBagLayout())
        gbc = awt.GridBagConstraints()

        info_label = JLabel("Enter one search term per line:")
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.gridwidth = 3
        settings_panel.add(info_label, gbc)

        self._grep_strings_area = JTextArea(15, 60)
        gbc.gridy = 1
        settings_panel.add(JScrollPane(self._grep_strings_area), gbc)

        gbc.gridwidth = 1

        gbc.insets = awt.Insets(10, 10, 10, 10)

        save_button = JButton("Save", actionPerformed=self._save_grep_strings)
        gbc.gridx = 0
        gbc.gridy = 2
        settings_panel.add(save_button, gbc)

        import_button = JButton("Import", actionPerformed=self._import_grep_strings)
        gbc.gridx = 1
        settings_panel.add(import_button, gbc)

        export_button = JButton("Export", actionPerformed=self._export_grep_strings)
        gbc.gridx = 2
        settings_panel.add(export_button, gbc)

        tabbedPane.addTab("Settings", settings_panel)

        # About tab
        about_panel = JPanel()
        about_panel.setLayout(awt.GridBagLayout())
        gbc = awt.GridBagConstraints()

        about_label = JLabel("Info Leakage Burp Extension - version {}".format(VERSION))
        gbc.gridx = 0
        gbc.gridy = 0
        about_panel.add(about_label, gbc)

        # Add the author label
        author_label = JLabel("Author: Mark Sowell")
        gbc.gridy = 1
        about_panel.add(author_label, gbc)

        tabbedPane.addTab("About", about_panel)

        self._main_panel.add(tabbedPane)

    def _import_grep_strings(self, event):
        file_chooser = JFileChooser()
        if file_chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            with open(file_chooser.getSelectedFile().getAbsolutePath(), "r") as f:
                grep_strings = json.load(f)
            self._grep_strings_area.setText("\n".join(grep_strings))

    def _export_grep_strings(self, event):
        file_chooser = JFileChooser()
        if file_chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
            with open(file_chooser.getSelectedFile().getAbsolutePath(), "w") as f:
                grep_strings = self._grep_strings_area.getText().split("\n")
                json.dump(grep_strings, f)

    def _save_grep_strings(self, event):
        global GREP_STRINGS
        GREP_STRINGS = self._grep_strings_area.getText().split("\n")
        self._callbacks.saveExtensionSetting("grep_strings", json.dumps(GREP_STRINGS))
        self.grep_strings_list = GREP_STRINGS
        # Show a popup indicating that the settings have been saved successfully
        JOptionPane.showMessageDialog(None, "Search terms have been saved successfully.", "Info", JOptionPane.INFORMATION_MESSAGE)


    def _load_grep_strings(self):
        global GREP_STRINGS
        grep_strings_str = self._callbacks.loadExtensionSetting("grep_strings")
        if grep_strings_str:
            GREP_STRINGS = json.loads(grep_strings_str)
            self._grep_strings_area.setText("\n".join(GREP_STRINGS))
            self.grep_strings_list = GREP_STRINGS

    # Implement ITab
    def getTabCaption(self):
        return "Info Leakage"

    def getUiComponent(self):
        return self._main_panel

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
