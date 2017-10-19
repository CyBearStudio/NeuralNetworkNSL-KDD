import pandas as pd
from sklearn.preprocessing import minmax_scale
from sklearn.neural_network import MLPClassifier

def load_data(file_path, cols=None):
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

    data = pd.read_csv(file_path, names=COL_NAMES, index_col=False)
    NOM_IND = [1, 2, 3]
    BIN_IND = [6, 11, 13, 14, 20, 21]
    # Need to find the numerical columns for normalization
    NUM_IND = list(set(range(40)).difference(NOM_IND).difference(BIN_IND))
    for num in NOM_IND:
        data.ix[:, num] = data.ix[:, num].astype('category')
        data.ix[:, num] = data.ix[:, num].cat.codes
    # Scale all numerical data to [0-1]
    data.ix[:, NOM_IND] = minmax_scale(data.ix[:, NOM_IND])
    data.ix[:, NUM_IND] = minmax_scale(data.ix[:, NUM_IND])
    labels = None
    if 'labels' in data.columns:
        labels = data['labels']
        # Binary labeling
        labels = labels.apply(lambda x: x if x =='normal' else 'anomaly')
        del data['labels']
    return [data, labels]


def train_test(data, labels, clf=None):
    if clf is None:
        clf = MLPClassifier(hidden_layer_sizes=(20,), alpha=.7,
                            beta_1=.8, beta_2=.8)
        clf.fit(data, labels)
    preds = clf.predict(data)
    return (sum(preds == labels)/len(preds), clf)

train_data, train_labels = load_data('data/KDDTrain+.csv')
train_correct, clf = train_test(train_data, train_labels)
print("Accuracy on training set: {0:1%}".format(train_correct))

test_data, test_labels = load_data('data/KDDTest+.csv')
test_correct, clf = train_test(test_data, test_labels, clf)
print("Accuracy on test set: {0:1%}".format(test_correct))
