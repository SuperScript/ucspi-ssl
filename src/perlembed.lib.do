dependon conf-perl conf-ldperl print-perlembed.sh
formake rm -f perlembed.lib
formake 'sh print-ldperl.sh > perlembed.lib'
rm -f perlembed.lib
sh print-ldperl.sh
exit 0
