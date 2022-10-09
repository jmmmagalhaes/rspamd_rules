#!/bin/bash

# Enable rspamd for all accounts

# All users need to block at least SOME mail on a shared server
for i in $(find /etc/virtual -name filter.conf); do sed -i 's/high_score_block=no/high_score_block=yes/g' $i; done

# If they have no filters configured, give them a baseline
for i in $(find /etc/virtual -name filter.conf)
        do
                if ! grep -q "high_score_block" $i; then
                        echo "high_score=15" >> $i
                        echo "high_score_block=yes" >> $i
                        echo "where=delete" >> $i
                fi
        done

# Rspamd configs won't be generated by DirectAdmin unless user_prefs exists, so handle it
for username in $(ls /usr/local/directadmin/data/users);
        do
                DIR=/home/$username/.spamassassin
                mkdir -p $DIR
                UP=$DIR/user_prefs
                  if [ ! -s ${UP} ]; then
                     echo 'required_score 15.0' > ${UP}
                     echo 'report_safe 1' >> ${UP}
                     chown $username:$username  ${UP}
                     chmod 644 ${UP}
        fi
        chown  ${username}:mail $DIR
        chmod 771 $DIR
done

# Rewrite Rspamd configs for users
echo "action=rewrite&value=rspamd" >> /usr/local/directadmin/data/task.queue
