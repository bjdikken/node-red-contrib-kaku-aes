-- TRUST protocol
-- by BJD 2019
trust_proto = Proto("trust","Trust Smart Home")
-- create a function to dissect it
function trust_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "TRUST"
    local subtree = tree:add(trust_proto,buffer(),"Trust Smart Home Protocol Data")
    subtree:add(buffer(0,1),"FrameNumber " .. buffer(0,1):uint())
    subtree:add(buffer(1,1),"SegmentNumber " .. buffer(1,1):uint())
--  subtree:add(buffer(2,1),"MessageType " .. buffer(2,1):uint())
    local typetext = ""
    local typeint = buffer(2,1):uint()
    if     typeint == 0 then typetext = "INVALID"
    elseif typeint == 1 then typetext = "COMMANDS_AVAILABLE"
    elseif typeint == 2 then typetext = "EVENT_NOTIFICATION"
    elseif typeint == 3 then typetext = "ANNOUNCEMENT"
    elseif typeint == 4 then typetext = "DEVICE_LINK_REQUEST"
    elseif typeint == 5 then typetext = "DEVICE_LINK_RESPONSE"
    elseif typeint == 6 then typetext = "GET_DEVICE_TIME"
    elseif typeint == 10 then typetext = "URL_REDIRECT"
    elseif typeint == 11 then typetext = "SYNC_ALL_DATA"
    elseif typeint == 12 then typetext = "STOP_SYNC_ALL_DATA"
    elseif typeint == 16 then typetext = "GET_DEVICE_INFO"
    elseif typeint == 17 then typetext = "UPDATE_USER_SETTINGS"
    elseif typeint == 18 then typetext = "GET_USER_SETTINGS"
    elseif typeint == 19 then typetext = "LOCAL_ENERGY_PRODUCTION"
    elseif typeint == 20 then typetext = "WEATHER_INFORMATION"
    elseif typeint == 21 then typetext = "VERSION_CHECK"
    elseif typeint == 22 then typetext = "GET_VERSION_LIST"
    elseif typeint == 23 then typetext = "VERSION_LIST"
    elseif typeint == 128 then typetext = "CONTROL_ENTITY"
    elseif typeint == 129 then typetext = "CREATE_ENTITY"
    elseif typeint == 130 then typetext = "DELETE_ENTITY"
    elseif typeint == 131 then typetext = "UPDATE_ENTITY"
    elseif typeint == 132 then typetext = "GET_ENTITY_STATUS"
    elseif typeint == 133 then typetext = "LIST_NEW_ENTITIES"
    elseif typeint == 134 then typetext = "GET_DATA_ENTITIES"
    elseif typeint == 135 then typetext = "LEARN_MODULE"
    elseif typeint == 136 then typetext = "GET_868_STATES"
    elseif typeint == 137 then typetext = "IDENTIFY_ZIGBEE"
    elseif typeint == 138 then typetext = "UPDATE_ZIGBEE"
    elseif typeint == 144 then typetext = "CONTROL_ZIGBEE"
    elseif typeint == 145 then typetext = "RESET_ZIGBEE"
    elseif typeint == 176 then typetext = "FIRMWARE_AVAILABLE"
    elseif typeint == 178 then typetext = "BACKUP_SYNC_START"
    elseif typeint == 179 then typetext = "BACKUP_SYNC_COMPLETE"
    elseif typeint == 180 then typetext = "REMOTE_REBOOT"
    elseif typeint == 91 then typetext = "FACTORY_DEFAULT_RESET_NOTIFICATION"
    elseif typeint == 251 then typetext = "REQUEST_NEXT_DATA_FRAME"
    elseif typeint == 252 then typetext = "ACKNOWLEDGE"
    elseif typeint == 253 then typetext = "NOT_ACKNOWLEDGE"
    elseif typeint == 254 then typetext = "NO_COMMANDS_AVAILABLE"
    end
    subtree:add(buffer(2,1),"MessageType " .. typeint .. " - " .. typetext)
    subtree:add(buffer(3,6),"MacAddressBytes " .. tostring(buffer(3,6):ether()))
    subtree:add(buffer(9,4),"MagicNumber " .. buffer(9,4):le_uint())
    subtree:add(buffer(13,2),"GlobalVersion " .. buffer(13,2):le_uint())
    subtree:add(buffer(15,2),"SettingsVersion " .. buffer(15,2):le_uint())
    subtree:add(buffer(17,2),"DeviceStateVersion " .. buffer(17,2):le_uint())
    subtree:add(buffer(19,2),"DeviceDataVersion " .. buffer(19,2):le_uint())
    subtree:add(buffer(21,2),"AreaDataVersion " .. buffer(21,2):le_uint())
    subtree:add(buffer(23,2),"RuleStateVersion " .. buffer(23,2):le_uint())
    subtree:add(buffer(25,2),"RuleDataVersion " .. buffer(25,2):le_uint())
    subtree:add(buffer(27,2),"SceneDataVersion " .. buffer(27,2):le_uint())
    subtree:add(buffer(29,4),"EntityId " .. buffer(29,4):le_uint())
    subtree:add(buffer(33,2),"SmartDeviceId " .. buffer(32,2):le_uint())
    subtree:add(buffer(37,4),"EntityTrackerID " .. buffer(37,4):le_uint())
    subtree:add(buffer(41,2),"DataLength " .. buffer(41,2):le_uint())
    local dleng = buffer(41,2):le_uint()
    subtree:add(buffer(43,dleng),"Data " .. tostring(buffer(43,dleng):bytes()))
end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 2012
udp_table:add(2012,trust_proto)