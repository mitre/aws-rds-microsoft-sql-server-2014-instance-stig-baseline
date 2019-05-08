# encoding: utf-8


include_controls 'microsoft-sql-server-2014-instance-stig-baseline' do

  control 'V-67759' do
    query = %(
	  SELECT
	      name
	  FROM
	      sys.sql_logins
	  WHERE
	      type_desc = 'SQL_LOGIN'
	      AND is_disabled = 0;
	)

	sql_session = mssql_session(user: attribute('user'),
	                              password: attribute('password'),
	                              host: attribute('host'),
	                              instance: attribute('instance'),
	                              port: attribute('port'))

	account_list = sql_session.query(query).column('name')

	 if account_list.empty?
	   impact 0.0
	   desc 'There are no sql managed accounts, control not applicable'

	   describe 'There are no sql managed accounts, control not applicable' do
	     skip 'There are no sql managed accounts, control not applicable'
	   end
	 else
	   account_list.each do |account|
	     describe "sql managed account: #{account}" do
	       subject { account }
	       it { should be_in SQL_MANAGED_ACCOUNTS }
	     end
	   end
	 end
  end

  control "V-67789" do
    impact 0.0
    describe 'If audit data were to become compromised, competent forensic analysis
    and discovery of the true source of potentially malicious system activity would
    be difficult, if not impossible, to achieve. In addition, access to audit
    records provides information an attacker could potentially use to his or her
    advantage.
      To ensure the veracity of audit data, the information system and/or the
    application must protect audit information from any and all unauthorized
    access. This includes read, write, copy, etc.
      SQL Server and third-party tools are examples of applications that are
    easily able to view and manipulate audit file data. Additionally, applications
    with user interfaces to audit records should not allow unfettered manipulation
    of, or access to, those records via any application. If an application provides
    access to the audit data, the application becomes accountable for ensuring that
    audit information is protected from unauthorized access.
      This requirement can be achieved through multiple methods, which will
    depend upon system architecture and design. Some commonly employed methods
    include ensuring log files enjoy the proper file system permissions utilizing
    file system protections, and limiting log data location.
      Audit information includes all information (e.g., audit records, audit
    settings, and audit reports) needed to successfully audit information system
    activity.' do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end

  control "V-67791" do
    impact 0.0
    describe 'If audit data were to become compromised, competent forensic analysis
    and discovery of the true source of potentially malicious system activity would
    be impossible to achieve.
      To ensure the veracity of audit data, the information system and/or the
    application must protect audit information from unauthorized modification.
      This requirement can be achieved through multiple methods, which will
    depend upon system architecture and design. Some commonly employed methods
    include ensuring log files enjoy the proper file system permissions, and
    limiting log data locations.
      Applications providing a user interface to audit data will leverage user
    permissions and roles identifying the user accessing the data and the
    corresponding rights that the user enjoys in order to make decisions regarding
    the modification of audit data.
      Audit information includes all information (e.g., audit records, audit
    settings, and audit reports) needed to successfully audit information system
    activity.
      Modification of database audit data could mask the theft or unauthorized
    modification of sensitive data stored in the database.' do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end

  control "V-67793" do
    impact 0.0
    describe 'If audit data were to become compromised, competent forensic analysis
    and discovery of the true source of potentially malicious system activity would
    be impossible to achieve.
      To ensure the veracity of audit data, the information system and/or the
    application must protect audit information from unauthorized deletion. This
    requirement can be achieved through multiple methods, which will depend upon
    system architecture and design.
      Some commonly employed methods include ensuring log files enjoy the proper
    file system permissions utilizing file system protections, restricting access,
    and backing up log data to ensure log data is retained.
      Applications providing a user interface to audit data will leverage user
    permissions and roles identifying the user accessing the data and the
    corresponding rights the user enjoys in order to make decisions regarding the
    deletion of audit data.
      Audit information includes all information (e.g., audit records, audit
    settings, and audit reports) needed to successfully audit information system
    activity.
      Deletion of database audit data could mask the theft or unauthorized
    modification of sensitive data stored in the database.' do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end

  control "V-67807" do
    impact 0.0
    describe 'When dealing with change control issues, it should be noted, any
    changes to the hardware, software, and/or firmware components of applications
    and tools related to SQL Server can potentially have significant effects on the
    overall security of the system. Only qualified and authorized individuals shall
    be allowed to obtain access to components related to SQL Server for purposes of
    initiating changes, including upgrades and modifications.
      Unmanaged changes that occur to the software libraries or configuration can
    lead to unauthorized or compromised installations.
      Of particular note in this context is that any software installed for
    auditing and/or audit file management must be protected and monitored.' do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end

  control "V-67825" do
    impact 0.0
    describe 'Information systems are capable of providing a wide variety of
    functions and services. Some of the functions and services, provided by default
    or selected for installation by an administrator, may not be necessary to
    support essential organizational operations (e.g., key missions, functions).
      Applications must adhere to the principles of least functionality by
    providing only essential capabilities.  Unused and unnecessary SQL Server
    components increase the number of available attack vectors.  By minimizing the
    services and applications installed on the system, the number of potential
    vulnerabilities is reduced.
      The SQL Server Reporting Services (SSRS) software component must be removed
    from SQL Server if it is unused.' do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end

  control "V-67827" do
    impact 0.0
    describe 'Information systems are capable of providing a wide variety of
    functions and services. Some of the functions and services, provided by default
    or selected for installation by an administrator, may not be necessary to
    support essential organizational operations (e.g., key missions, functions).
      Applications must adhere to the principles of least functionality by
    providing only essential capabilities.  Unused and unnecessary SQL Server
    components increase the number of available attack vectors.  By minimizing the
    services and applications installed on the system, the number of potential
    vulnerabilities is reduced.
      The SQL Server Integration Services (SSIS) software component must be
    removed from SQL Server if it is unused.' do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end

  control "V-67829" do
    impact 0.0
    describe 'Information systems are capable of providing a wide variety of
    functions and services. Some of the functions and services, provided by default
    or selected for installation by an administrator, may not be necessary to
    support essential organizational operations (e.g., key missions, functions).
      Applications must adhere to the principles of least functionality by
    providing only essential capabilities.  Unused and unnecessary SQL Server
    components increase the number of available attack vectors.  By minimizing the
    services and applications installed on the system, the number of potential
    vulnerabilities is reduced.
      The SQL Server Analysis Service (SSAS) software component removed from SQL
    Server if it is unused.' do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end

  control "V-67831" do
    impact 0.0
    describe 'Information systems are capable of providing a wide variety of
    functions and services. Some of the functions and services, provided by default
    or selected for installation by an administrator, may not be necessary to
    support essential organizational operations (e.g., key missions, functions).
      Applications must adhere to the principles of least functionality by
    providing only essential capabilities.  Unused and unnecessary SQL Server
    components increase the number of available attack vectors.  By minimizing the
    services and applications installed on the system, the number of potential
    vulnerabilities is reduced.
      The SQL Server Distributed Replay Client software component must be removed
    if it is unused.' do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end

  control "V-67833" do
    impact 0.0
    describe 'Information systems are capable of providing a wide variety of
    functions and services. Some of the functions and services, provided by default
    or selected for installation by an administrator, may not be necessary to
    support essential organizational operations (e.g., key missions, functions).
      Applications must adhere to the principles of least functionality by
    providing only essential capabilities.  Unused and unnecessary SQL Server
    components increase the number of available attack vectors.  By minimizing the
    services and applications installed on the system, the number of potential
    vulnerabilities is reduced.
      The SQL Server Distributed Replay Controller software component must be
    removed if it is unused.' do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end

  control "V-67835" do
    impact 0.0
    describe 'Information systems are capable of providing a wide variety of
    functions and services. Some of the functions and services, provided by default
    or selected for installation by an administrator, may not be necessary to
    support essential organizational operations (e.g., key missions, functions).
      Applications must adhere to the principles of least functionality by
    providing only essential capabilities.  Unused and unnecessary SQL Server
    components increase the number of available attack vectors.  By minimizing the
    services and applications installed on the system, the number of potential
    vulnerabilities is reduced.
      The Full-Text Search software component must be removed from SQL Server if
    it is unused.' do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end

  control "V-67837" do
    impact 0.0
    describe 'Information systems are capable of providing a wide variety of
    functions and services. Some of the functions and services, provided by default
    or selected for installation by an administrator, may not be necessary to
    support essential organizational operations (e.g., key missions, functions).
      Applications must adhere to the principles of least functionality by
    providing only essential capabilities.  Unused and unnecessary SQL Server
    components increase the number of available attack vectors.  By minimizing the
    services and applications installed on the system, the number of potential
    vulnerabilities is reduced.
      The Master Data Services software component must be removed from SQL Server
    if it is unused.' do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end

  control "V-67841" do
    impact 0.0
    describe 'Information systems are capable of providing a wide variety of
    functions and services. Some of the functions and services, provided by default
    or selected for installation by an administrator, may not be necessary to
    support essential organizational operations (e.g., key missions, functions).
      Applications must adhere to the principles of least functionality by
    providing only essential capabilities.  Unused and unnecessary SQL Server
    components increase the number of available attack vectors.  By minimizing the
    services and applications installed on the system, the number of potential
    vulnerabilities is reduced.
      The Data Quality Client software component must be removed from SQL Server
    if it is unused.' do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end

  control "V-67843" do
    impact 0.0
    describe 'Information systems are capable of providing a wide variety of
    functions and services. Some of the functions and services, provided by default
    or selected for installation by an administrator, may not be necessary to
    support essential organizational operations (e.g., key missions, functions).
      Applications must adhere to the principles of least functionality by
    providing only essential capabilities.  Unused and unnecessary SQL Server
    components increase the number of available attack vectors.  By minimizing the
    services and applications installed on the system, the number of potential
    vulnerabilities is reduced.
      The Data Quality Services software component must be removed from SQL
    Server if it is unused.' do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end

  control "V-67845" do
    impact 0.0
    describe 'Information systems are capable of providing a wide variety of
    functions and services. Some of the functions and services, provided by default
    or selected for installation by an administrator, may not be necessary to
    support essential organizational operations (e.g., key missions, functions).
      Applications must adhere to the principles of least functionality by
    providing only essential capabilities.  Unused and unnecessary SQL Server
    components increase the number of available attack vectors.  By minimizing the
    services and applications installed on the system, the number of potential
    vulnerabilities is reduced.
      The Client Tools Software Development Kit must be removed from SQL Server
    if it is unused.' do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end

  control "V-67847" do
    impact 0.0
    describe 'Information systems are capable of providing a wide variety of
    functions and services. Some of the functions and services, provided by default
    or selected for installation by an administrator, may not be necessary to
    support essential organizational operations (e.g., key missions, functions).
      Applications must adhere to the principles of least functionality by
    providing only essential capabilities.  Unused and unnecessary SQL Server
    components increase the number of available attack vectors.  By minimizing the
    services and applications installed on the system, the number of potential
    vulnerabilities is reduced.
      Management Tools is an indispensable software component on any server
    running the SQL Server DBMS, if the database administrator logs on to the
    Windows server to do his/her work.  However, it is also possible to use the
    management tools on a separate machine and still connect to SQL Server.  If
    this approach is used and DBAs never need to use the Management Tools directly
    on the server, then the Management Tools software component must be removed
    from the server.' do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end

  control "V-67851" do
    impact 0.0
    describe 'SQL Server is capable of providing a wide variety of functions and
    services. Some of the functions and services, provided by default, may not be
    necessary to support essential organizational operations (e.g., key missions,
    functions).
      It is detrimental for applications to provide, or install by default,
    functionality exceeding requirements or mission objectives. Examples include,
    but are not limited to, installing advertising software demonstrations, or
    browser plug-ins not related to requirements or providing a wide array of
    functionality not required for every mission, but which cannot be disabled.
      Applications must adhere to the principles of least functionality by
    providing only essential capabilities.
      Unused and unnecessary SQL Server components increase the number of
    available attack vectors to SQL Server by introducing additional targets for
    attack. By minimizing the services and applications installed on the system,
    the number of potential vulnerabilities is reduced. Components of the system
    that are unused and cannot be uninstalled must be disabled.' do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end

  control "V-67871" do
    impact 0.0
    describe 'Use of weak or not validated cryptographic algorithms undermines the
    purposes of utilizing encryption and digital signatures to protect data.  Weak
    algorithms can be easily broken and not validated cryptographic modules may not
    implement algorithms correctly. Unapproved cryptographic modules or algorithms
    should not be relied on for authentication, confidentiality or integrity. Weak
    cryptography could allow an attacker to gain access to and modify data stored
    in the database as well as the administration settings of SQL Server.
      Applications, including DBMSs, utilizing cryptography are required to use
    approved NIST FIPS 140-2 validated cryptographic modules that meet the
    requirements of applicable federal laws, Executive Orders, directives,
    policies, regulations, standards, and guidance.
      Operations that require the use of cryptography include the provisioning of
    digital signatures, the generation and validation of cryptographic hashes, and
    the protection of data by storing and transmitting it in encrypted form.
      The security functions validated as part of FIPS 140-2 for cryptographic
    modules are described in FIPS 140-2 Annex A.
      SQL Server complies with FIPS 140-2 if Windows is configured to do so.
      NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based
    encryption modules.' do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end

  control "V-67881" do
    impact 0.0
    describe 'Applications, including DBMSs, must prevent unauthorized and
    unintended information transfer via shared system resources. Permitting only
    DBMS processes and authorized, administrative users to have access to the files
    where the database resides helps ensure that those files are not shared
    inappropriately and are not open to backdoor access and manipulation.' do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end

  control "V-67897" do
    impact 0.0
    describe "If time stamps are not consistently applied and there is no common
    time reference, it is difficult to perform forensic analysis, in audit files,
    trace files/tables, and application data tables.
      Time is commonly expressed in Coordinated Universal Time (UTC), a modern
    continuation of Greenwich Mean Time (GMT), or local time with an offset from
    UTC.  SQL Server obtains the date and time from the Windows operating system.
    In a normal configuration, the OS obtains them from an official time server,
    using Network Time Protocol (NTP).  The ultimate source is the United States
    Naval Observatory Master Clock.
      SQL Server built-in functions for retrieving current timestamps are:  (high
    precision) sysdatetime(), sysdatetimeoffset(), sysutcdatetime();  (lower
    precision) CURRENT_TIMESTAMP or getdate(), getutcdate().
      Provided the operating system is synchronized with an official time server,
    these timestamp-retrieval functions are automatically compliant with this
    requirement, as are SQL Server's audit and trace capabilities." do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end

  control "V-70623" do
    impact 0.0
    describe 'The SQL Server Browser simplifies the administration of SQL Server,
    particularly when multiple instances of SQL Server coexist on the same
    computer.  It avoids the need to hard-assign port numbers to the instances and
    to set and maintain those port numbers in client systems.  It enables
    administrators and authorized users to discover database management system
    instances, and the databases they support, over the network.
      This convenience also presents the possibility of unauthorized individuals
    gaining knowledge of the available SQL Server resources.  Therefore, it is
    necessary to consider whether the SQL Server Browser is needed.  Typically, if
    only a single instance is installed, using the default name (MSSQLSERVER) and
    port assignment (1433), the Browser is not adding any value.   The more complex
    the installation, the more likely SQL Server Browser is to be helpful.
      This requirement is not intended to prohibit use of the Browser service in
    any circumstances; rather, it calls for administrators and management to
    consider whether the benefits of its use outweigh the potential negative
    consequences.' do
      skip 'This is set as Not Applicable given the vendor manages this via the PaaS platform for the service'
    end
  end
end
