#!/usr/bin/env ruby

#Performs basic file integrity monitoring and reporting, using MD5 hashes and other basic file data.  Imports a list of files to scan,
# creates a base line and allows periodic comparisons and CSV reporting.

#Nov 2012 - Simon Moffatt
#http://www.github.com/smof/fingeprint


module Fingerprint
  
  require 'rubygems'
  require 'digest/md5'
  require 'csv'
  require 'openssl'
  require 'base64'
  require 'getoptlong'
  require 'rdoc'
  
  class Main
    
    #Globals ###################################################################################################################################
    $date=Time.now.strftime("%d-%m-%Y_%H%M")
    $init_file ="reports/init.rc" #Stores initialisation hashes.  
    $master_file_list="reports/master_file_list" #contains list of files to be scanned.  Full path of the file to be scanned.  One file per line.
    $baseline_report="reports/baseline_report.csv" #initial baseline report file
    $scan_report="reports/scan_report_#{$date}.csv" #periodic report file
    $diff_report = "reports/diff_report_#{$date}.csv" #diff report showing hash mismatches
    #encryption properties
    $cipher = OpenSSL::Cipher.new('aes-256-cbc')
    $key = Base64.encode64("averylongkeythatwillshouldcomefromthecommandline")
    #Globals ###################################################################################################################################
    
    
    def self.help
      
      puts "Usage: fingerprint [OPTION]"
      puts ""
      puts "--help, -h          show help"
      puts "--encrypt, -e       encrypt an existing report file"
      puts "--decrypt, -d       decrypt an existing report file"
      puts "--analyse, -a       perform a diff analysis between an existing baseline and periodic scan report"
      puts "--scan, -s          perform a current scan of files from the master file list"
      puts "--init, -i          creates a new baseline report, replaces all previous baseline and scanned reports, snapshots the master file list"
      puts ""
      puts "Example: ruby fingerprint.rb --init"
      puts ""
      puts "The reports/ directory will contain the published baseline, scan and diff reports."
      puts "Populate the #{$master_file_list} with a list of files to scan.  One file path per line."
            
    end
    
    
    #initialises app, deletes previous reports, creates baseline and takes hashes for file_list and baseline report pumping into init store
    def self.init
      
      #get a dir listing of the reports/ directory excluding the init file
      existing_report_files = Dir.entries("reports")
      existing_report_files.delete($master_file_list.split("/")[1])
           
     
      #delete all files in reports/ directory      
      existing_report_files.each do |file| 
        unless File.directory?(file)
           File.delete("reports/#{file}") 
         end 
      end
      
      #only start the baseline report if the master_file_list has been populated     
      if File.size?($master_file_list).nil?
        
        puts ""
        puts "ERROR: #{$master_file_list} is empty.  Please populate with a list of files to monitor.  One file path per line"
        puts "Eg."
        puts "Cat #{$master_file_list}"
        puts "/bin/dmesg"
        puts "/bin/ntfsdump_logfile"
        puts "/bin/init-checkconf"
        puts "/bin/cat"
        puts "..."
        
      else
       
          #create baseline report
          perform_scan "baseline"
     
          #snapshot master file list and baseline report hashes
          init_hashes =[]
          init_hashes << "#{$master_file_list}, #{create_hash_for_file($master_file_list)}"
          init_hashes << "#{$baseline_report}, #{create_hash_for_file($baseline_report)}"
       
          #write out the init file
          init_file = File.open($init_file,"w")
          init_hashes.each do |line| init_file.puts line end #basic puts but driven to open file
          init_file.close #closes
          
          #encrypt the init file
          encrypt_file $init_file
                
      end     
        
       
       
    end

    #checks that the master_file_list has not been tampered with since the last init ran - checks hashes in init.rc with those of actual file
    def self.check_master_file_list
      
      decrypted_init =[]
      #decrypt init.rc file and parse decrypted stream into an array
      CSV.parse(decrypt_file "reports/init.enc") do |line|
        
        decrypted_init << line
        
      end
      
      puts array_of_decrypted_file[1]
      
    end



    #Create baseline hash report file
    def self.perform_scan(type="periodic")
    
    check_master_file_list
    
            
        if type == "periodic"
             
          report_file = $scan_report
        
        elsif type == "baseline"
          
          report_file = $baseline_report
          
        end

=begin        
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
          
             puts "CREATE_REPORT: Can't find master file list!"      
  
           end
        
        end #ends CSV.open
      
      
=end        
    end

    #creates MD5 hash of file
    def self.create_hash_for_file filepath

       if File.file?(filepath) #only create a hash if file exists and path isn't a non-file (dir/socket/dev etc) 
         
         md5_hash = Digest::MD5.hexdigest(File.read(filepath))
        
        else
          
          md5_hash = "File not found or a directory"
           
       end
    end


    #encrypts file argument
    def self.encrypt_file file
      $cipher.encrypt
      $cipher.key = $key
       
      
      if File.exists? file           
        #create an encrypted output file with a .enc extension.  Uses existing file, splits and changes extention
        encrypted_output_file = "#{File.dirname(file)}/#{File.basename(file).split(".")[0]}.enc"
      
        buf="" #empty buffer
        File.open(encrypted_output_file, "wb") do |outf|
          File.open(file, "rb") do |inf|
                while inf.read(4096, buf)
                    outf << $cipher.update(buf)
                end
               outf << $cipher.final
          end
       end
      
       File.delete file
     
      else
       puts "ENCRYPTION:  Can't find #{file}"
       
      end
      
      
    end
    
    #decrypts file argument into a byte steam that doesnt get written back to a file obj
    def self.decrypt_file file
      
      $cipher.decrypt
      $cipher.key = $key
      
            
      if File.exists? file      
        #create an new decrypted output file, changing the input file extension to .dec
        #decrypted_output_file = "#{File.dirname(file)}/#{File.basename(file).split(".")[0]}.dec"
      
       buf = "" #empty buffer
       #File.open(decrypted_output_file, "wb") do |outf|
       outf = "" # output file stream 
        File.open(file, "rb") do |inf|
            while inf.read(4096, buf)
             outf << $cipher.update(buf)
            end
          outf << $cipher.final
        end
      #end

     else
       puts "DECRYPTION: Can't find #{file}" 
      end
      
      #return stream of decrypted file in form of string
      return outf
      
    end


    #Compares baseline report and periodic report for any differences
    def self.perform_diff
      
      #before performing diff, check that the baseline and master file list haven't been tampered with
      decrypt_file $init_file
      
      
      
      
      
      
      
      
      #produce a list of available periodic report files to use for comparison
      scan_report_files = Dir.entries("reports/") #dir *
      scan_report_files.keep_if {|file| file.include? "scan"} #pull out only the periodic_report files
      
      puts ""
      puts "The following scan report files where found:"
      puts "================================================"
      scan_report_files.each_index do |index| puts "[#{index}] #{scan_report_files[index]}" end
      puts ""
      puts "Select number of file to use for comparison:"
      selected_scan_file = scan_report_files[gets.chomp.to_i]  
      
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