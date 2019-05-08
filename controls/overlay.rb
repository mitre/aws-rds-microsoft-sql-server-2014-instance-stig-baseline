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
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  control "V-67791" do
    impact 0.0
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  control "V-67793" do
    impact 0.0
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  control "V-67807" do
    impact 0.0
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  control "V-67825" do
    impact 0.0
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  control "V-67827" do
    impact 0.0
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  control "V-67829" do
    impact 0.0
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  control "V-67831" do
    impact 0.0
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  control "V-67833" do
    impact 0.0
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  control "V-67835" do
    impact 0.0
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  control "V-67837" do
    impact 0.0
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  control "V-67841" do
    impact 0.0
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  control "V-67843" do
    impact 0.0
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  control "V-67845" do
    impact 0.0
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  control "V-67847" do
    impact 0.0
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  control "V-67851" do
    impact 0.0
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  control "V-67871" do
    impact 0.0
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  control "V-67881" do
    impact 0.0
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  control "V-67897" do
    impact 0.0
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  control "V-70623" do
    impact 0.0
    describe 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on' do
      skip 'This control is not applicable on microsoft sql within aws rds, as aws manages the operating system in which the microsoft sql database is running on'
    end
  end

  include_controls 'microsoft-sql-server-2014-database-stig-baseline' do

  end

end
