
#To be executed in data/ directory
#concat.csv is the concatenated file of all csv files

cat Monday-WorkingHours.pcap_ISCX.csv >> concat.csv
sed 1d Tuesday-WorkingHours.pcap_ISCX.csv >> concat.csv
sed 1d Wednesday-workingHours.pcap_ISCX.csv >> concat.csv
sed 1d Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv >> concat.csv
sed 1d Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv >> concat.csv
sed 1d Friday-WorkingHours-Morning.pcap_ISCX.csv >> concat.csv
sed 1d Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv >> concat.csv
sed 1d Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv >> concat.csv
