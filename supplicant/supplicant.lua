#!/usr/bin/lua
nixio = require "nixio"
bit = nixio.bit
md5 = require "md5"
--iconv = require "iconv"
log = {}
bool = {}
--日志最低优先级的值
log_priority_min = 0

function string.split(input, delimiter)  
    local input = tostring(input) 
    local delimiter = tostring(delimiter)  
    if (delimiter=='') then return false end  
    local pos = 0
	local arr = {}  
    -- for each divider found  
	for st,sp in function() return string.find(input,delimiter,pos,true) end do
		table.insert(arr,string.sub(input,pos,st-1))
		pos = sp+1
	end
    table.insert(arr, string.sub(input, pos))  
    return arr  
end

function string.trim(str)
	return (str:gsub("^%s*(.-)%s*$", "%1"))
end

function string.isNilOrEmpty(str)
	if(type(str) == "nil") then
		return true
	elseif(type(str) == "string") then
		if(string.trim(str) == "") then
			return true
		else
			return false
		end
	else
		return true
	end
end

function bool.isTrue(flag)
	if(type(flag) == "boolean" and flag == true) then
		return true
	else
		return false
	end
end

--查找指定数组中的某个元素的位置，如找到则返回索引位置，未找到返回nil
function table.find(_table,_value,_begin,_end)
	local _begin = _begin or 1
	local _end = _end or #(_table)
	for k,v in ipairs(_table) do
		if(k >= _begin and k <= _end and v == _value) then 
			return k
		end
	end
	return nil
end

--对指定数组进行截取，从指定开始位置到结束位置，返回截取后的数组子集
function table.sub(_table,_begin,_end)
	local _begin = _begin or 1
	local _end = _end or #(_table)
	local subtable = {}
	local k = 1
	for i=_begin,_end do
		subtable[k] = _table[i]
		k = k + 1
	end
	return subtable
end

function sleep(n)
   os.execute("sleep " .. n)
end

--获取日志优先级是否允许, 默认最低优先级是0 -- log_priority_min
-- 参数level			返回值
--	debug		log_priority_min
--	warn			   +1
--	info			   +2
--	error			   +3
function log.priority(level)
	--默认配置级别warn,log_level在配置文件中配置
	if(string.isNilOrEmpty(log_level)) then
		log_level = "warn"
	end
	local conf_level = log_priority_min + 1;
	if(log_level == "debug") then
		conf_level = log_priority_min;
	elseif(log_level == "warn") then
		conf_level = log_priority_min + 1;
	elseif(log_level == "info") then
		conf_level = log_priority_min + 2;
	elseif(log_level == "error") then 
		conf_level = log_priority_min + 3;
	else
		conf_level = log_priority_min + 1;
	end
	if(level == "debug") then
		return conf_level <= log_priority_min;
	elseif(level == "warn") then
		return conf_level <= log_priority_min + 1;
	elseif(level == "info") then
		return conf_level <= log_priority_min + 2;
	elseif(level == "error") then
		return conf_level <= log_priority_min + 3;
	end;
end

function log.debug(msg)
	if(log.priority("debug")) then
		log.msg(" [debug] "..msg)
	end
end

function log.warn(msg)
	if(log.priority("warn")) then
		log.msg(" [ warn] "..msg)
	end
end

function log.info(msg)
	if(log.priority("info")) then
		log.msg(" [ info] "..msg);
	end
end

function log.error(msg)
	if(log.priority("error")) then
		log.msg(" [error] "..msg);
	end
end

function log.printStatus(msg)
	local file = io.open(status_file, "w")
	file:write(msg)
	file:close()
end

function log.msg(msg)
	local logfile = io.open(log_file, "a")
	logfile:write(os.date("%m/%d %X",os.time())..msg.."\n")
	logfile:close()
end

function encrypt(buffer)
    for i,v in ipairs(buffer) do
		buffer[i] = bit.bor(bit.rshift(bit.band(buffer[i], 0x80),6),
							bit.rshift(bit.band(buffer[i], 0x40),4),
							bit.rshift(bit.band(buffer[i], 0x20),2),
							bit.lshift(bit.band(buffer[i], 0x10),2),
							bit.lshift(bit.band(buffer[i], 0x08),2),
							bit.lshift(bit.band(buffer[i], 0x04),2),
							bit.rshift(bit.band(buffer[i], 0x02),1),
							bit.lshift(bit.band(buffer[i], 0x01),7))
	end
end

function decrypt(buffer)
    for i,v in ipairs(buffer) do
        buffer[i] = bit.bor(bit.rshift(bit.band(buffer[i], 0x80),7),
							bit.rshift(bit.band(buffer[i], 0x40),2),
							bit.rshift(bit.band(buffer[i], 0x20),2),
							bit.rshift(bit.band(buffer[i], 0x10),2),
							bit.lshift(bit.band(buffer[i], 0x08),2),
							bit.lshift(bit.band(buffer[i], 0x04),4),
							bit.lshift(bit.band(buffer[i], 0x02),6),
							bit.lshift(bit.band(buffer[i], 0x01),1))
	end
end

function search_service(mac_addr)
	local packet_len = 1 + 1 + 16 + 1 + 1 + 5 + 1 + 1 + 6
	local packet = {}
	table.insert(packet, 0x07)
	table.insert(packet, packet_len)
	for i=1,16 do
		table.insert(packet, 0)
	end
	table.insert(packet, 0x08)
	table.insert(packet, 0x07)
	for i=0,4 do
		table.insert(packet,i)
	end
	table.insert(packet, 0x07);
	table.insert(packet, 0x08);
	for k,v in ipairs(string.split(mac_addr,':')) do
		table.insert(packet,string.format("%d","0x"..v))
	end
	
	--将packet内容由整型转换为字节
	local bpacket = {}
	for k,v in ipairs(packet) do
		table.insert(bpacket,string.char(v))
	end
	--摘要计算校验和
	
	local md5str = md5.sumhexa(table.concat(bpacket))
	--将校验和加入到packet[3..18]
	for i=1,string.len(md5str) do
		if(i%2==0) then
			packet[i/2+2] = string.format("%d","0x"..string.sub(md5str,i-1,i))
		end
	end
	
	encrypt(packet);
	
	local bpacket = {}
	for k,v in ipairs(packet) do
		table.insert(bpacket,string.char(v))
	end
	
	local recv_msg = send_recv(table.concat(bpacket))
	if(not recv_msg) then return nil end

	local recv_packet = {}
	for i=1,string.len(recv_msg) do
		recv_packet[i] = string.byte(string.sub(recv_msg,i,i))
	end
	
	decrypt(recv_packet)
	if(check_md5(recv_packet)) then
		--取出服务内容
		local service_index = table.find(recv_packet, 0x0a)
		local service_len = recv_packet[service_index + 1];
		local service_type = table.sub(recv_packet, service_index + 2, service_len + service_index - 1)
		local service = {}
		for k,v in ipairs(service_type) do
			table.insert(service,string.char(v))
		end
		local service_str = table.concat(service)
		return service_str;
	else
		return search_service(mac_addr)
	end

end

function search_server_ip(mac_addr, ip)
	local packet_len = 1 + 1 + 16 + 1 + 1 + 5 + 1 + 1 + 16 + 1 + 1 + 6;
	local packet = {};
	
	table.insert(packet, 0x0c)
	table.insert(packet, packet_len)
	for i=1,16 do
		table.insert(packet, 0x00)
	end
		
	table.insert(packet, 0x08)
	table.insert(packet, 0x07)
	for i=0,4 do
		table.insert(packet,i)
	end
	
	table.insert(packet, 0x09)
	table.insert(packet, 0x12)
	for i=1,string.len(ip) do      
		table.insert(packet,string.byte(string.sub(ip,i,i)))
	end
	for i=1,16-string.len(ip) do      
		table.insert(packet, 0x00)
	end
	
	table.insert(packet, 0x07)
	table.insert(packet, 0x08)
	for k,v in ipairs(string.split(mac_addr,':')) do
		table.insert(packet,string.format("%d","0x"..v))
	end
	
	--将packet内容由整型转换为字节
	local bpacket = {}
	for k,v in ipairs(packet) do
		table.insert(bpacket,string.char(v))
	end
	--摘要计算校验和
	
	local md5str = md5.sumhexa(table.concat(bpacket))
	--将校验和加入到packet[3..18]
	for i=1,string.len(md5str) do
		if(i%2==0) then
			packet[i/2+2] = string.format("%d","0x"..string.sub(md5str,i-1,i))
		end
	end
	
	encrypt(packet);
	
	local bpacket = {}
	for k,v in ipairs(packet) do
		table.insert(bpacket,string.char(v))
	end
	
	local recv_msg = send_recv(table.concat(bpacket))
	if(not recv_msg) then return nil end

	local recv_packet = {}
	for i=1,string.len(recv_msg) do
		recv_packet[i] = string.byte(string.sub(recv_msg,i,i))
	end
	
	decrypt(recv_packet)
	if(check_md5(recv_packet)) then 
		--取出服务器ip
		local server_index = table.find(recv_packet, 0x0c)
		local server_len = recv_packet[server_index + 1];
		local server_ip = table.sub(recv_packet, server_index + 2, server_index + server_len - 1)
		local host_ip = ""
		for k,v in ipairs(server_ip) do
			host_ip = host_ip..tostring(v).."."
		end
		host_ip = string.sub(host_ip,1,string.len(host_ip)-1)
		return host_ip;
	else
		return search_server_ip(mac_addr, ip)
	end
	
end

function generate_login(mac_addr, ip, user, pwd, dhcp, service, version)
	local packet = {}
	table.insert(packet, 0x01) -- 1 请求上线
	packet_len = string.len(user) + 2 + 
				 string.len(pwd) + 2 +
				 string.len(ip) + 2 +
				 string.len(service) + 2 +
				 string.len(dhcp) + 2 +
				 string.len(version) + 2 +
				 16 + 2 + 
				 6 + 2
	table.insert(packet,packet_len)
	for i=1,16 do
		table.insert(packet, 0x00)
	end
	
	table.insert(packet, 0x07)
	table.insert(packet, 0x08)
	for k,v in ipairs(string.split(mac_addr,':')) do
		table.insert(packet,string.format("%d","0x"..v))
	end
	
	table.insert(packet, 0x01)
	table.insert(packet,string.len(user) + 2)
	for i=1,string.len(user) do      
		table.insert(packet,string.byte(string.sub(user,i,i)))
	end
	
	table.insert(packet, 0x02)
	table.insert(packet,string.len(pwd) + 2)
	for i=1,string.len(pwd) do      
		table.insert(packet,string.byte(string.sub(pwd,i,i)))
	end
	
	table.insert(packet, 0x09)
	table.insert(packet,string.len(ip) + 2)
	for i=1,string.len(ip) do      
		table.insert(packet,string.byte(string.sub(ip,i,i)))
	end
	
	table.insert(packet, 0x0a)
	table.insert(packet, string.len(service) + 2)
	for i=1,string.len(service) do      
		table.insert(packet,string.byte(string.sub(service,i,i)))
	end
	
	table.insert(packet, 0x0e)
	table.insert(packet, string.len(dhcp) + 2)
	for i=1,string.len(dhcp) do      
		table.insert(packet,tonumber(string.sub(dhcp,i,i)))
	end
	
	table.insert(packet, 0x1f)
	table.insert(packet, string.len(version) + 2)
	for i=1,string.len(version) do      
		table.insert(packet,string.byte(string.sub(version,i,i)))
	end
	
	--将packet内容由整型转换为字节
	local bpacket = {}
	for k,v in ipairs(packet) do
		table.insert(bpacket,string.char(v))
	end
	--摘要计算校验和
	
	local md5str = md5.sumhexa(table.concat(bpacket))
	--将校验和加入到packet[3..18]
    for i=1,string.len(md5str) do
		if(i%2==0) then
			packet[i/2+2] = string.format("%d","0x"..string.sub(md5str,i-1,i))
		end
	end
	
    encrypt(packet)
	
	local bpacket = {}
	for k,v in ipairs(packet) do
		table.insert(bpacket,string.char(v))
	end
    return table.concat(bpacket)
end

function login(packet)
	log.debug("Entered function login().")
	log.debug("Sending a login packet...")
	local recv_msg = send_recv(packet)
	if(not recv_msg) then 
		net_status = -2
		log.debug("Receive timeout, no response pacekt was received.")
		return nil
	end
	log.debug("Received a response packet, decrypting...")
	local recv_packet = {}
	for i=1,string.len(recv_msg) do
		recv_packet[i] = string.byte(string.sub(recv_msg,i,i))
	end
    decrypt(recv_packet)
	log.debug("The packet has been decrypted, MD5 checking...")
	--md5校验
	if(check_md5(recv_packet)) then
		log.debug("MD5 check success! Getting the state...")
		status = recv_packet[21]
		session_len = recv_packet[23]
		session = table.sub(recv_packet, 24, session_len + 24 - 1)
		pos = table.find(recv_packet, 0x0b, session_len + 24)
		message_len = recv_packet[pos + 1]
		message = table.sub(recv_packet, pos + 2, message_len + pos + 2 - 1)
		msg = {}
		for k,v in ipairs(message) do
			table.insert(msg, string.char(v))
		end
		msg_str = table.concat(msg)
		--trans = iconv.new("utf-8","gbk")
		--msg_str = trans:iconv(msg_str)
		--log(msg_str)
		if(status == 0) then
			--认证出错，可能是用户名密码错误，也可能是不在上网时段，
			--或者不是有效用户，或者被管理员禁止认证
			--具体原因在msg_str中给出，但需要gbk解码
			net_status = -3
			log.debug("Login failure!")
			return nil
		else
			net_status = 1
			log.debug("Login success!")
			return session
		end
	else
		net_status = -1
		log.debug("MD5 check failure!")
		return nil
	end
    
end

function generate_breathe(mac_addr, ip, session, index)
    local indexstr = string.format("%x", index)
    local packet = {}
	table.insert(packet, 0x03) --3 保持在线  5 请求下线  1 请求上线
    local packet_len = #(session) + 88
	table.insert(packet, packet_len)
	for i=1,16 do
		table.insert(packet, 0x00)
	end
	table.insert(packet, 0x08)
	table.insert(packet, #(session) + 2)
	for k,v in ipairs(session) do      
		table.insert(packet, v)
	end
	table.insert(packet, 0x09)
	table.insert(packet, 0x12)
	for i=1,string.len(ip) do      
		table.insert(packet,string.byte(string.sub(ip,i,i)))
	end
	for i=1,16-string.len(ip) do      
		table.insert(packet,0x00)
	end
	table.insert(packet, 0x07)
	table.insert(packet, 0x08)
	for k,v in ipairs(string.split(mac_addr,':')) do
		table.insert(packet,string.format("%d","0x"..v))
	end
	table.insert(packet, 0x14)
	table.insert(packet, 0x06)
	
	local len = string.len(indexstr)
	table.insert(packet,string.format("%d","0x"..string.sub(indexstr, len-7, len-6)))
	table.insert(packet,string.format("%d","0x"..string.sub(indexstr, len-5, len-4)))
	table.insert(packet,string.format("%d","0x"..string.sub(indexstr, len-3, len-2)))
	table.insert(packet,string.format("%d","0x"..string.sub(indexstr, len-1, len-0)))
	
	local block = { 0x2a, 0x06, 0, 0, 0, 0, 
					0x2b, 0x06, 0, 0, 0, 0, 
					0x2c, 0x06, 0, 0, 0, 0, 
					0x2d, 0x06, 0, 0, 0, 0, 
					0x2e, 0x06, 0, 0, 0, 0, 
					0x2f, 0x06, 0, 0, 0, 0}

	for k,v in ipairs(block) do
		table.insert(packet, v)
	end
	
	--将packet内容由整型转换为字节
	local bpacket = {}
	for k,v in ipairs(packet) do
		table.insert(bpacket,string.char(v))
	end
	--摘要计算校验和
	
	local md5str = md5.sumhexa(table.concat(bpacket))
	--将校验和加入到packet[3..18]
    for i=1,string.len(md5str) do
		if(i%2==0) then
			packet[i/2+2] = string.format("%d","0x"..string.sub(md5str,i-1,i))
		end
	end
	
    encrypt(packet)
	
     --for k,v in ipairs(packet) do io.write(v,', ') end
	
	local bpacket = {}
	for k,v in ipairs(packet) do
		table.insert(bpacket,string.char(v))
	end
    return table.concat(bpacket)
end

function breathe(mac_addr, ip, session, index)
	log.debug("Entered function breathe().")
    sleep(30)
	md5err_cnt = 0
    while(true) do
		local breathe_packet = generate_breathe(mac_addr, ip, session, index)
		log.debug("Sending a breathe packet, index: "..index)
		local recv_msg = send_recv(breathe_packet)
		if(not recv_msg) then
			net_status = -4
			log.debug("Receive timeout, no response pacekt was received.")
			return nil 
		end
		log.debug("Received a response packet, decrypting...")

		local recv_packet = {}
		for i=1,string.len(recv_msg) do
			recv_packet[i] = string.byte(string.sub(recv_msg,i,i))
		end
		decrypt(recv_packet)
		log.debug("The packet has been decrypted, MD5 checking...")
		if(check_md5(recv_packet)) then
			log.debug("MD5 check success! Getting the state...")
			status = recv_packet[21]
			if status == 1 then
				--在线
				net_status = 1
				log.debug("Breathe success!")
			else
				--呼吸出错
				net_status = -6
				log.debug("Breathe error!")
				return
			end
		else
			net_status = -5
			log.debug("MD5 check failure!")
			md5err_cnt = md5err_cnt + 1
			if(md5err_cnt >= 3) then
				return
			end
		end
		index = index + 3
		log.debug("Waiting for 30 seconds...")
		sleep(30)
	end
end

function generate_logout(mac_addr, ip, session, index)
    index = string.format("%x",index)
    local packet = {}
	table.insert(packet, 0x05) -- 5 请求下线  3 保持在线  1 请求上线
    local packet_len = #(session) + 88
	table.insert(packet, packet_len)
	for i=1,16 do
		table.insert(packet, 0x00)
	end
	table.insert(packet, 0x08)
	table.insert(packet, #(session) + 2)
	for k,v in ipairs(session) do      
		table.insert(packet, v)
	end
	table.insert(packet, 0x09)
	table.insert(packet, 0x12)
	for i=1,string.len(ip) do      
		table.insert(packet,string.byte(string.sub(ip,i,i)))
	end
	for i=1,16-string.len(ip) do      
		table.insert(packet, 0x00)
	end
	table.insert(packet, 0x07)
	table.insert(packet, 0x08)
	for k,v in ipairs(string.split(mac_addr,':')) do
		table.insert(packet,string.format("%d","0x"..v))
	end
	table.insert(packet, 0x14)
	table.insert(packet, 0x06)
	
	local len = string.len(index)
	table.insert(packet,string.format("%d","0x"..string.sub(index,len-7,len-6)))
	table.insert(packet,string.format("%d","0x"..string.sub(index,len-5,len-4)))
	table.insert(packet,string.format("%d","0x"..string.sub(index,len-3,len-2)))
	table.insert(packet,string.format("%d","0x"..string.sub(index,len-1,len-0)))
	
	
	local block = { 0x2a, 0x06, 0, 0, 0, 0, 
					0x2b, 0x06, 0, 0, 0, 0, 
					0x2c, 0x06, 0, 0, 0, 0, 
					0x2d, 0x06, 0, 0, 0, 0, 
					0x2e, 0x06, 0, 0, 0, 0, 
					0x2f, 0x06, 0, 0, 0, 0}

	for k,v in ipairs(block) do
		table.insert(packet, v)
	end
	
	--将packet内容由整型转换为字节
	local bpacket = {}
	for k,v in ipairs(packet) do
		table.insert(bpacket,string.char(v))
	end
	--摘要计算校验和
	
	local md5str = md5.sumhexa(table.concat(bpacket))
	--将校验和加入到packet[3..18]
    for i=1,string.len(md5str) do
		if(i%2==0) then
			packet[i/2+2] = string.format("%d","0x"..string.sub(md5str,i-1,i))
		end
	end
	
    encrypt(packet)
	
	local bpacket = {}
	for k,v in ipairs(packet) do
		table.insert(bpacket,string.char(v))
	end
    return table.concat(bpacket)
end

function logout(mac_addr, ip, session, index)
	log.debug("Entered function logout().")
	index = index + 3
	logout_packet = generate_logout(mac_addr, ip, session, index)
	log.debug("Sending a logout packet...")
	send(logout_packet)
	local recv_msg = receive()
	net_status = 0 --下线
	log.debug("Now offline.")
end

--接收报文
function receive()
	local recv_msg = udp:recv(4096)
	return recv_msg
end

--发送报文
function send(msg)
	udp:send(msg)
end

--发送并接收
function send_recv(msg)
	local time_out_cnt = 3
	local recv_msg = nil
	while(time_out_cnt > 0) do
		--发送报文
		send(msg)
		--接收报文
		recv_msg = receive()
		if(recv_msg) then break end
		time_out_cnt = time_out_cnt - 1
	end
	return recv_msg
end

--md5校验
function check_md5(packet)
	local recv_md5 = {}
	for i=3, 18 do
		table.insert(recv_md5,packet[i])
		packet[i] = 0x00
	end
	print()
	--将packet内容由整型转换为字节
	local bpacket = {}
	for k,v in ipairs(packet) do
		table.insert(bpacket,string.char(v))
	end
	local md5str = md5.sumhexa(table.concat(bpacket))
	local md5_packet = {}
	for i=1,string.len(md5str) do
		if(i%2==0) then
			md5_packet[i/2] = string.format("%d","0x"..string.sub(md5str,i-1,i))
		end
	end
	return table.concat(md5_packet) == table.concat(recv_md5)
end

function connect()
	log.debug("Entered function connect().")
	net_status = 0;
	index = 0x01000000
	login_packet = generate_login(mac_addr, ip, username, password, dhcp, service, version)
	session = login(login_packet)
	if(session) then
		retry_cnt = 0
		log.printStatus("online")
		log.info("Connecting the internet success！")
		breathe(mac_addr, ip, session, index)
	end
	if(net_status ~= 1 and net_status ~= -3) then
		logout(mac_addr, ip, session, index)
	end
end

function search()
	
	if(string.isNilOrEmpty(host_ip)) then
		udp:connect("1.1.1.8", 3850)
		host_ip = search_server_ip(mac_addr, ip)
	end
	if(string.isNilOrEmpty(host_ip)) then
		log.error("Failed to search for server host ip.")
		return false
	end

	log.info("Server IP: "..host_ip)
	udp:connect(host_ip, port)
	if(string.isNilOrEmpty(service)) then
		--udp:setpeername(host_ip, port)
		service = search_service(mac_addr)
	end
	if(string.isNilOrEmpty(service)) then
		log.warn("Failed to search internet service. Using the default service 'int', if it's not right, please configure service in 'bin/conf.lua'")
		service = "int"
		--return false
	end

	log.info("Service: "..service)
	return true
end

function init()
	--log.info("Loading configuration files.")
	dofile(config_file)
	pcall(dofile, config_file)
	dofile(authc_file)
	pcall(dofile, authc_file)
	port = 3848

	udp = nixio.socket("inet","dgram")
	udp:setopt("socket","reuseaddr",1)
	udp:setopt("socket","rcvtimeo",10)
	
	if(string.isNilOrEmpty(ip)) then
		udp:connect("1.1.1.8", 3850)
		ip = udp:getsockname()
	end
	
	os.execute("echo -n > "..log_file)
	log.info("Mac Addr: "..mac_addr)
	log.info("Local IP: "..ip)
	log.info("Username: "..username)
	log.info("Password: "..password)
	
end

function main()
	local connect_cnt = 0;
	init()
	local flag = autostart
	while(flag) do
		--记录连接次数
		connect_cnt = connect_cnt + 1
		log.printStatus("connecting")
		if(search()) then
			connect()
			log.printStatus("offline")
			if(net_status == -3) then
				--认证失败，不再自动连接
				log.error("Authentication failure： The authentication information is incorrect, or not in internet time period.")
				flag = false;
			elseif(net_status == -2 or net_status == -1) then
				--连接超时，3秒后重新连接
				log.error("Authentication failure： connect timeout, try reconnecting...")
				sleep(3)
			else
				--保持连接失败，3秒后重新连接
				log.error("Hold on connecting failed, try reconnecting...")
				sleep(3)
			end
		else
			--搜索服务失败，60秒后再次搜索
			log.printStatus("offline")
			sleep(60)
		end
	end
end

home = "/usr/share/supplicant"
config_file = home.."/conf.lua"
authc_file = home.."/supplicant.conf"
log_file = home.."/info.log"
status_file = home.."/supplicant.status"
net_status = 0
main()
