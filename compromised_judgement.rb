#! /usr/bin/env ruby
###########################################################################
#
# [+] Description: Companion script to Compromised. Compares list of breached accounts to AD dump of 'Last Password Change' dates.
# [+] Use Case: Determine if an account is highly susceptible to a password replay attack because its password hasn't changed since being involved in a breach. The assumption is that the account itself is compromised or that the user is using the same password for their comp'd account and product account. This data is obviously less useful if an org doesn't enforce a password re-use or expiration policy.
#
#                           ~ author: nxkennedy ~
###########################################################################

#******** Usage ********#
# ruby compromised_judgement.rb <pwned-emails*.csv> <ActiveDirectory-dump.csv>
#
# ** IMPORTANT **
# <ActiveDirectory-dump.csv> contents expected to be in the following format:
# LoginUserStatus,EmailAddress,LastPwdChange
# 1,email@gmail.com,2016-07-31
# 99,email2@gmail.com,NULL
#
# Output: vuln2PwdReplay(#{today}).csv will contain the following columns:
# ["Account", "Status", "BreachDate", "LastPwdChange", "ResetRequired"]
#**********************#


require 'csv'
require 'date'
require 'paint'
require 'progress_bar'
#require_relative './performance_test'




####### Clear the terminal screen ruby style and print our banner #########
print "\e[2J\e[f"
banner = <<EOB

---:----::-------.`                                 `:+.
---::---:-----:-.`                          --`     `-syo`
---::---------:-.`                        `/+.      ``-/+/
---:------------`                         .-`.`      `-oo-
---------------.                           `..`       `:oo.
---------------`                           ./:.`      `/hNh`
-----------.--.`                           oho-`      `-yNN:
------.----...``                           +ds:`      `.oNMs
-.----.---.``                              :hy/.`      .+NMd.
-.----.--.`                               `-yh+.`      `:hNm:
-.----.-.``      ``````                 `+o+os-`       `./oo-
..----..`   ```...`..-/+/:.          ``-`:.`...`       `.+o/`
..---..`````.....-+yo+oydNd/..--:. `/o/:     `...`     `.sdy:
..--.``...``.`.:/+shhyssymNo```-/.-...       `/:`       `:+/:
....```.`````.yo////ddhs/sh/``..-`.          ``.-`     `.+y+`
...````.``` :yhysso//hh/..-/.```   `..         ..`       `.`
.`````.``  :y+oyyhhy++s:...`....``...
```````    ys/:::/yhyo/:::-..:oyy:
.`.```    -ds+///::+sso-`....-/oyh.        `     `````````````````````
-..``     +y/-.:++/--//.``...-/o/-       `     `````````````````````````````````
-...`     :+::-..:/:--.`....-:/:`        `````````````````````..................
-.....`````:/:---.........---.`````````````````````````.........................
---.......-:--................................```````````````............-------
----------::::--------------------.......```                     ```..----------
:---------::::::::::::::::::::::--------    COMPROMISED PT. II:    ```----------
//::------//+++++++++++////++++++++////        JUDGEMENT DAY        ````+ooooooo
:-------::/++/////++++////////+++//////                               ````/ooooo
EOB

puts Paint[banner, :red, :bold]

####### Specify files to compare #########
@breachinfo = ARGV[0]
@lastpasschange = ARGV[1]

#######  nifty performance testing add-on ( just uncomment them and the 'ends') #########
#print_memory_usage do
    #print_time_spent do

#######  Count lines for progress bar #########
fileLen = 0
CSV.foreach(@breachinfo, headers: true) do |count|
    fileLen += 1
end
puts Paint["\n COMPARING BREACH EVIDENCE TO PASSWORD RESET DATES...\n", :cyan]
progress = ProgressBar.new(fileLen)
today = Date.today.to_s

####### Begin Writing to CSV #########
CSV.open("vuln2PwdReplay(#{today}).csv", 'w+') do |csvWriter|
    csvWriter << [
        "Account",
        "Status",
        "BreachDate",
        "LastPwdChange",
        "ResetRequired",
        ]

    alerts = 0
    alertList = []
    requiresReset = 0
    cleared = 0
    previouslyEvaluated = [] # To fight dupes in either file

    # Account Codes from AD dump file that require tranlsation
    statusCode = {
        "0" => "Not Active",
        "1" => "Active",
        "2" => "Locked Out",
        "3" => "Banned",
        "4" => "Deleted",
        "6" => "Invited",
        "99" => "Deleted",
    }

    ####### Begin reading loop #########
    CSV.foreach(@breachinfo, headers: true) do |data1|
        account = data1["Account"]
        finding = data1["Finding"]
        mostRecentBreachFlag = data1["MostRecent"]
        CSV.foreach(@lastpasschange, :row_sep => :auto, headers: true) do |data2|
            account2 = data2["EmailAddress"]
            passChange = data2["LastPwdChange"]
            status = data2["LoginUserStatus"]

            ####### Evaluation Time #########
            # Writes to file all accounts that were found to be compromised by Compromised script.

            # If it wasn't found in HIBP...
            if (finding == "Not Found")
                previouslyEvaluated << account
                break
            # Or if we've already looped through this account...
            # this works because the first account entry is the most recent, any following occurences are unimportant
            elsif (previouslyEvaluated.include?(account))
                break
            # Now, if account names match and the breach flag is set...
            elsif (account == account2 && mostRecentBreachFlag == "x")
            dateBreached = Date.parse(data1["BreachDate"])

                # Flag passwords that have never been reset with date == NEVER and set ResetRequired flag
                if (passChange == "NULL")
                        csvWriter << [
                            account,
                            statusCode[status],
                            dateBreached.to_s,
                            "NEVER",
                            "x",
                        ]
                        requiresReset += 1
                        previouslyEvaluated << account
                        break
                else
                    dateChanged = Date.parse(passChange)
                end

                # Evaluate whether password change or breach came first, if so mark with an 'x' flag
                if (dateChanged < dateBreached)
                    csvWriter << [
                        account,
                        statusCode[status],
                        dateBreached.to_s,
                        dateChanged.to_s,
                        "x",
                    ]
                    requiresReset += 1
                else
                    csvWriter << [
                        account,
                        statusCode[status],
                        dateBreached.to_s,
                        dateChanged.to_s,
                        nil,
                    ]
                    cleared += 1
                end

                previouslyEvaluated << account
            else
                # pass it like a python
            end

        end

        # Now check our array to see if we've evaluated the account. If not, the account wasn't included in the comparison file.
        if (!previouslyEvaluated.include?(account))
            alertList << account
            alerts += 1
        end

        progress.increment!
    end

####### Final Output #########
puts Paint["\n\n JURY DELIBERATION AND SENTENCING COMPLETE", :cyan]
puts "___"
puts Paint["[☠] SENTENCED TO IMMEDIATE RESET: #{requiresReset.to_s}", :red]
puts Paint["[✓] CLEARED OF ALL CHARGES: #{cleared.to_s}", :green]
puts Paint["[⚡] DID NOT STAND TRIAL: #{alerts.to_s}", :yellow]
puts Paint[alertList.to_s, :yellow]
puts "\n"
end

####### These last ends are for the performance testing #########
    #end
#end
