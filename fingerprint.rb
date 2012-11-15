#!/usr/bin/env ruby

#Performs basic file integrity monitoring and reporting, using MD5 hashes and other basic file data.  Imports a list of files to scan,
# creates a base line and allows periodic comparisons and CSV reporting.

#Nov 2012 - Simon Moffatt
#http://www.github.com/smof/fingerprint


module Fingerprint
  
  require 'rubygems'
  require 'digest/md5'
  require 'csv'
  require 'openssl'
  require 'base64'
  require 'getoptlong'
  require 'rdoc'
  require 'socket'
  
  class Main
    
    #Globals ###################################################################################################################################
    $date=Time.now.strftime("%d-%m-%Y_%H%M")
    $reports_dir = "reports/"
    $log_file = "#{$reports_dir}fingerprint.log"
    $write_to_logs = false #false to turn off logs
    $init_file = "#{$reports_dir}.init.rc" #Stores initialisation hashes.  Hidden and encrypted  
    $master_file_list = "#{$reports_dir}master_file_list" #contains list of files to be scanned.  Full path of the file to be scanned.  One file per line.
    $baseline_report = "#{$reports_dir}baseline_report.csv" #initial baseline report file
    $scan_report = "#{$reports_dir}scan_report_#{$date}.csv" #periodic report file
    $diff_report = "#{$reports_dir}diff_report_#{$date}.csv" #diff report showing hash mismatches
    #encryption properties
    $cipher = OpenSSL::Cipher.new('aes-256-cbc')
    $key = Base64.encode64("As33dkeywhich15quitelongbutnott00long#{Socket.gethostname}") #adds in local machine name to lock to same machine
    #Globals ###################################################################################################################################
    
    
    #Log writer
    def self.write_log log_message
      
      date=Time.now.strftime("%d-%m-%Y_%H:%M:%S") #more detailed date as $date can't contain :
      
      unless $write_to_logs == false
        
        File.open($log_file,"a") do |log|
      
          log.puts "#{date} Fingerprint.rb #{log_message}"
         
        end
        
      end
      
    end
    
    
    
    def self.help
      
      puts "Usage: fingerprint [OPTION]"
      puts ""
      puts "--help, -h          show this help message"
      puts "--init, -i          creates a new baseline report, replaces all previous scanned reports, snapshots the master file list and baseline report"
      puts "--scan, -s          perform a current scan of files from the master file list"
      puts "--diff, -d          perform a diff analysis between the current baseline and a selected periodic scan report"
      puts ""
      puts "Example: ruby fingerprint.rb --init"
      puts ""
      puts "The #{$reports_dir} directory will contain the published baseline, scan and diff reports."
      puts "Populate the #{$master_file_list} with a list of files to scan.  One file path per line."
            
    end
    
    
    #initialises app, deletes previous reports, creates baseline and takes hashes for file_list and baseline report pumping into init store
    def self.init
                    
      #get a dir listing of the reports/ directory excluding the init file
      existing_report_files = Dir.entries($reports_dir)
      
      if File.exists?($master_file_list)
          
          STDOUT.puts "Remove existing #{$master_file_list}? [y/n]"
          remove_master_file_list_answer = gets.chomp.to_s.downcase
          answers=["y","n"]
          while !answers.include? remove_master_file_list_answer do
              STDOUT.puts "Remove existing #{$master_file_list} [y/n]?"
              remove_master_file_list_answer = gets.chomp.to_s.downcase  
          end      
      
          #if you want to keep the existing master file list in place
          if remove_master_file_list_answer.eql? "n" 
            existing_report_files.delete($master_file_list.split("/")[1])
                    
          end
      
      end
          
      #delete all files in reports/ directory      
      existing_report_files.each do |file| 
        unless File.directory?(file)
           File.delete("#{$reports_dir}#{file}") 
         end 
      end
      
      write_log "--init started"
      write_log "Existing report files deleted"
            
      #only start the baseline report if the master_file_list has been populated     
      if File.size?($master_file_list).nil?
        
        STDOUT.puts "#{$master_file_list} is empty or missing.  Please populate and rerun fingerprint.rb --init"
        write_log "master_file_list not populated"
        
      else
       
          #create baseline report
          perform_scan "baseline"
                   
          #snapshot master file list and baseline report hashes
          init_hashes = Hash.new
          init_hashes[$master_file_list] = create_hash_for_file($master_file_list)
          init_hashes[$baseline_report] =  create_hash_for_file($baseline_report)     
       
          #write out the encrypted init file
          $cipher.encrypt
          $cipher.key = $key #need to concatentate the local user and machine name to this seed key to make it slightly more secure!
                             
          File.open($init_file, "w") do |file|
           
              file.write $cipher.update(init_hashes.to_s)
              file.write $cipher.final
              write_log ".init.rc created"
                       
          end
                         
      end     
        
       
       
    end

    #checks that the master_file_list has not been tampered with since the last init ran - checks hashes in init.rc with current hash of actual file
    def self.check_master_file_list
      
      write_log "--scan started.  #{$master_file_list} being checked for consistency"
      #decrypt init.rc file and rip out the hash for the master_file_list.  This is dirty.  Basically a hash as a string being manually stripped. Replace.
      recovered_master_file_list_hash = decrypt_init.split(",")[0].split("=>")[1].gsub("\"","")
     
      #compare the recovered hash from the init with a newly created hash for the master_file_list.  return true or recovered hash value
      file_ok = recovered_master_file_list_hash == create_hash_for_file($master_file_list) ? true : recovered_master_file_list_hash
      
      if file_ok == true
        
        write_log "#{$master_file_list} found to be consistent"
        
      else
        
        write_log "Inconsistencies found with #{$master_file_list}"
        write_log "Stored Hash: #{file_ok}"
        write_log "Current Hash: #{create_hash_for_file($master_file_list)}"
        write_log "Run Fingerprint.rb --init to reset"
        
      end
      
      return file_ok
      
    end

    #checks that the baseline_report file has not been tampered with since the last init ran - checks hashes in init.rc with current hash of actual file
    def self.check_baseline_report
      
      write_log "-diff started.  #{$baseline_report} being checked for consistency"
      
      #decrypt init.rc file and rip out the hash for the baseline_report file.  Needs replacing with something more robust
      recovered_baseline_report_hash = decrypt_init.split(",")[1].split("=>")[1].gsub("\"","").gsub("}","")
     
      #compare the recovered hash from .init.rc with a newly created hash for the master_file_list.  return true or recovered hash value
      file_ok = recovered_baseline_report_hash == create_hash_for_file($baseline_report) ? true : recovered_baseline_report_hash
      
      if file_ok == true
        
        write_log "#{$baseline_report} found to be consistent"
        
      else
        
        write_log "Inconsistencies found with #{$baseline_report}"
        write_log "Stored Hash: #{file_ok}"
        write_log "Current Hash: #{create_hash_for_file($baseline_report)}"
        write_log "Run Fingerprint.rb --init to reset"
        
      end
      
      return file_ok
      
    end


    #Create baseline hash report file
    def self.perform_scan(type="periodic")
    
    #check that the master file list hasn't been tampered with before going ahead and creating a new scan file.  don't bother with check if runnig baseline
    if (type == "baseline") || (check_master_file_list == true)
              
        if type == "periodic"
             
          report_file = $scan_report
        
        elsif type == "baseline"
          
          report_file = $baseline_report
          
        end

       #write out report 
        CSV.open(report_file, 'wb') do |record|
          
          record << ["File", "MD5 Hash", "File Last Modify Date", "Size(bytes)"] #header
          
           if File.exist?($master_file_list) #check master list actually exists...
         
              CSV.foreach($master_file_list,'r') do |file| #read in each file from master file list...
         
                  if File.file?(file[0]) #perform hash entry on file only if file in the master file list actually exists
          
                     record << [file[0], create_hash_for_file(file[0]), File.mtime(file[0]), File.size(file[0])]
                                          
                  else
                            
                      record << [file[0], "File not found or a directory", "File not found or a directory", "File not found or a directory"]
                  
                 end
            
              end      
                      
           else
       
             end
        
        end #ends CSV.open
          
         STDERR.puts "#{report_file} created"
         write_log "#{report_file} created"     
               
                
       
    else    #if check_master_file_list returns false
      
      STDERR.puts "Can't perform scan!!!  Inconsistencies found with #{$master_file_list}.  See #{$log_file}"
            
    end #ends check_master_file_list if
  

    end



    #creates MD5 hash of file
    def self.create_hash_for_file filepath

       if File.file?(filepath) #only create a hash if file exists and path isn't a non-file (dir/socket/dev etc) 
         
         md5_hash = Digest::MD5.hexdigest(File.read(filepath))
        
        else
          
          md5_hash = "File not found or a directory"
           
       end
    end


      
    #decrypts the .init.rc file and returns a string
    def self.decrypt_init
      
      $cipher.decrypt
      $cipher.key = $key
        
      #check the init file exists            
      if File.exists? $init_file      
              
        buf = "" #empty buffer
        outf = "" # output file stream 
       
        File.open($init_file, "rb") do |file|
            while file.read(4096, buf)
             outf << $cipher.update(buf)
            end
          outf << $cipher.final
        end

      else
       
       return
       
      end
      
      #return stream of decrypted file in form of string
      return outf
      
    end


    #Compares baseline report and periodic report for any differences
    def self.perform_diff
      
      #Need to do a check of the baseline report integrity before continuing
      if check_baseline_report == true

        #produce a list of available periodic report files to use for comparison
        scan_report_files = Dir.entries("reports/") #dir *
        scan_report_files.keep_if {|file| file.include? "scan"} #pull out only the periodic_report files
      
        puts ""
        puts "The following scan report files where found:"
        puts "================================================"
        scan_report_files.each_index do |index| puts "[#{index}] #{scan_report_files[index]}" end
        puts ""
        puts "Select number of file to use for comparison:"
        selected_value = gets.chomp.to_i
        #check number selected is actually in the reports index       
        
        while !scan_report_files.each_index.include?(selected_value) do
            puts "Select number of file to use for comparison:"
            selected_value=gets.chomp.to_i
        end
           
        selected_scan_file = scan_report_files[selected_value]
                      
        #perform comparison against the baseline report outputting to a diff_report
        CSV.open($diff_report, 'wb') do |record|
        
          record << ["File", "Baseline_Hash", "Scanned_Hash", "Baseline_Date_Last_Modified", "Scanned_Date_Last_Modified", "Baseline_Size", "Scanned_Size"]
        
           CSV.foreach($baseline_report,{:headers=>:first_row}) do |baseline_entry|
       
             CSV.foreach("reports/#{selected_scan_file}",{:headers=>:first_row}) do |scan_entry|
           
               #when finding file entry in both files check hash value for both files is different, if it is, create entry in diff report...
               if (baseline_entry[0] == scan_entry[0]) && (baseline_entry[1] != scan_entry[1])
             
                   record << [baseline_entry[0],baseline_entry[1],scan_entry[1],baseline_entry[2],scan_entry[2],baseline_entry[3],scan_entry[3]]
                  
               end #ends if
                
             end #ends CSV.foreach
           
           end #ends CSV.foreach
         
        end  #ends CSV.open     
      
        STDOUT.puts "Diff reported created.  See #{$diff_report} for more details."
        write_log "#{$diff_report} created"
              
     else #check_baseline_report is false
            
      STDERR.puts "Can't perform diff!!!  Inconsistencies found with #{$baseline_report}.  See #{$log_file}"
       
     end #ends check_baseline_report if
                    
    end

    #set options
    opts = GetoptLong.new(
      [ '--help', '-h', GetoptLong::NO_ARGUMENT ],
      [ '--init', '-i', GetoptLong::NO_ARGUMENT ],
       [ '--scan', '-s', GetoptLong::NO_ARGUMENT ],
       [ '--diff', '-d', GetoptLong::NO_ARGUMENT ]
    )

    #flash an error message unless 
    unless ARGV[0]
      puts "Option missing - (try --help)\n"
      exit
    end

    #Processes command line arguments
    opts.each do |opt,arg|

      case opt

      when '--help'

            help

      when '--scan'
        
        perform_scan
        
      when '--diff'
        
        perform_diff
        
      when '--init'
          
          init
          
      else
        
          help
          
      end

    end

    
    
  end

end