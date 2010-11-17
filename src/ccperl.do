dependon conf-ccperl conf-perl print-ccperl.sh
formake rm -f ccperl
formake 'sh print-ccperl.sh > ccperl'
rm -f ccperl
sh print-ccperl.sh
exit 0
