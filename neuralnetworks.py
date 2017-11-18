"""K-Means Classifier"""
import pandas as pd
from sklearn.preprocessing import minmax_scale
from sklearn.neural_network import MLPClassifier

COL_NAMES = ["duration", "protocol_type", "service", "flag", "src_bytes",
             "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
             "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
             "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
             "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
             "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
             "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
             "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
             "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
             "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "labels"]

ATTACKS = {
    'normal': 'normal',

    'back': 'DoS',
    'land': 'DoS',
    'neptune': 'DoS',
    'pod': 'DoS',
    'smurf': 'DoS',
    'teardrop': 'DoS',
    'mailbomb': 'DoS',
    'apache2': 'DoS',
    'processtable': 'DoS',
    'udpstorm': 'DoS',

    'ipsweep': 'Probe',
    'nmap': 'Probe',
    'portsweep': 'Probe',
    'satan': 'Probe',
    'mscan': 'Probe',
    'saint': 'Probe',

    'ftp_write': 'R2L',
    'guess_passwd': 'R2L',
    'imap': 'R2L',
    'multihop': 'R2L',
    'phf': 'R2L',
    'spy': 'R2L',
    'warezclient': 'R2L',
    'warezmaster': 'R2L',
    'sendmail': 'R2L',
    'named': 'R2L',
    'snmpgetattack': 'R2L',
    'snmpguess': 'R2L',
    'xlock': 'R2L',
    'xsnoop': 'R2L',
    'worm': 'R2L',

    'buffer_overflow': 'U2R',
    'loadmodule': 'U2R',
    'perl': 'U2R',
    'rootkit': 'U2R',
    'httptunnel': 'U2R',
    'ps': 'U2R',
    'sqlattack': 'U2R',
    'xterm': 'U2R'
}

class NeuralNetworkNSL():

    def __init__(self):
        self.clf = None
        self.training = []
        self.testing = []

    def load_data(self, filepath):
        data = pd.read_csv(filepath, names=COL_NAMES, index_col=False)
        # Shuffle data
        data = data.sample(frac=1).reset_index(drop=True)
        NOM_IND = [1, 2, 3]
        BIN_IND = [6, 11, 13, 14, 20, 21]
        # Need to find the numerical columns for normalization
        NUM_IND = list(set(range(40)).difference(NOM_IND).difference(BIN_IND))
        # Convert nominal to category codes
        for num in NOM_IND:
            data.iloc[:, num] = data.iloc[:, num].astype('category')
            data.iloc[:, num] = data.iloc[:, num].cat.codes
        # Scale all numerical data to [0-1]
        data.iloc[:, NOM_IND] = minmax_scale(data.iloc[:, NOM_IND])
        data.iloc[:, NUM_IND] = minmax_scale(data.iloc[:, NUM_IND])
        labels = data['labels']
        del data['labels']
        return [data, labels]

    def load_training_data(self, filepath):
        self.training = self.load_data(filepath)

    def load_test_data(self, filepath):
        self.testing = self.load_data(filepath)

    def train_clf(self):
        train_data, train_labels = self.training
        bin_labels = train_labels.apply(lambda x: x if x == 'normal' else 'anomaly')
        self.clf = MLPClassifier(hidden_layer_sizes=(20,), alpha=.7,
                                 beta_1=.8, beta_2=.8)
        self.clf.fit(train_data, bin_labels)

    def test_clf(self, train=False):
        if train:
            data, labels = self.training
        else:
            data, labels = self.testing
        bin_labels = labels.apply(lambda x: x if x == 'normal' else 'anomaly')
        test_preds = self.clf.predict(data)
        test_acc = sum(test_preds == bin_labels)/len(test_preds)
        return [test_preds, test_acc]

    def evaluate_results(self, ans=None, train=False):
        if not ans:
            ans = self.test_clf(train)
        print("Accuracy on data: {0:1%}".format(ans[1]))
        return ans
