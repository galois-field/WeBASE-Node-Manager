-- ----------------------------
-- 1、init tb_account_info data   admin/Abcd1234
-- ----------------------------
INSERT INTO tb_account_info (account, account_pwd, role_id, create_time, modify_time)
values ('admin', '$2a$10$F/aEB1iEx/FvVh0fMn6L/uyy.PkpTy8Kd9EdbqLGo7Bw7eCivpq.m', 100000, now(), now());



-- ----------------------------
-- 2、init tb_role data
-- ----------------------------
INSERT INTO tb_role (role_name, role_name_zh, create_time, modify_time)
VALUES ('admin', '管理员', now(), now());
INSERT INTO tb_role (role_name, role_name_zh, create_time, modify_time)
VALUES ('visitor', '普通用户', now(), now());
INSERT INTO tb_role (role_name, role_name_zh, create_time, modify_time)
VALUES ('developer', '开发者', now(), now());

-- ----------------------------
-- 3、init tb_method (repeated methodId is removed, ex: remove(string))
-- ----------------------------
-- (system config info 0x1000) setValueByKey
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xbd291aef', 0,
        '{"constant":false,"inputs":[{"name":"key","type":"string"},{"name":"value","type":"string"}],"name":"setValueByKey","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
-- (table factory 0x1001) createTable openTable
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x56004b6a', 0,
        '{"constant":false,"inputs":[{"name":"tableName","type":"string"},{"name":"key","type":"string"},{"name":"valueField","type":"string"}],"name":"createTable","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());

-- TODO 与v143-v150中重复
-- INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
-- VALUES ('0xf23f63c9', 0,
--         '{"constant":true,"inputs":[{"name":"","type":"string"}],"name":"openTable","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"}',
--         'function', 1, now(), now());
-- (crud info 0x1002) update select remove insert(same as cns's insert)
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x2dca76c1', 0,
        '{"constant":false,"inputs":[{"name":"tableName","type":"string"},{"name":"key","type":"string"},{"name":"entry","type":"string"},{"name":"condition","type":"string"},{"name":"optional","type":"string"}],"name":"update","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x983c6c4f', 0,
        '{"constant":true,"inputs":[{"name":"tableName","type":"string"},{"name":"key","type":"string"},{"name":"condition","type":"string"},{"name":"optional","type":"string"}],"name":"select","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xa72a1e65', 0,
        '{"constant":false,"inputs":[{"name":"tableName","type":"string"},{"name":"key","type":"string"},{"name":"condition","type":"string"},{"name":"optional","type":"string"}],"name":"remove","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xa216464b', 0,
        '{"constant":false,"inputs":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"addr","type":"string"},{"name":"abi","type":"string"}],"name":"insert","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
-- (consensus info node manage 0x1003) addObserver addSealer remove
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x2800efc0', 0,
        '{"constant":false,"inputs":[{"name":"nodeID","type":"string"}],"name":"addObserver","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x89152d1f', 0,
        '{"constant":false,"inputs":[{"name":"nodeID","type":"string"}],"name":"addSealer","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x80599e4b', 0,
        '{"constant":false,"inputs":[{"name":"nodeID","type":"string"}],"name":"remove","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
-- (cns info 0x1004) selectByName selectByNameAndVersion // insert(ignored, same as crud's insert method: insert(string,string,string,string)
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x819a3d62', 0,
        '{"constant":true,"inputs":[{"name":"name","type":"string"}],"name":"selectByName","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x897f0251', 0,
        '{"constant":true,"inputs":[{"name":"name","type":"string"},{"name":"version","type":"string"}],"name":"selectByNameAndVersion","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
-- INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time) VALUES ('0xa216464b', 0, '{"constant":false,"inputs":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"addr","type":"string"},{"name":"abi","type":"string"}],"name":"insert","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}', 'function', 1, now(), now());
-- (permission manage 0x1005) insert queryByName remove grantWrite revokeWrite
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x06e63ff8', 0,'{"constant":false,"inputs":[{"name":"table_name","type":"string"},{"name":"addr","type":"string"}],"name":"insert","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}','function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x20586031', 0,
        '{"constant":true,"inputs":[{"name":"table_name","type":"string"}],"name":"queryByName","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x44590a7e', 0,
        '{"constant":false,"inputs":[{"name":"table_name","type":"string"},{"name":"addr","type":"string"}],"name":"remove","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());

-- TODO 与v143-v150中重复
-- INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
-- VALUES ('0x96ec37c4', 0,
--         '{"constant":false,"inputs":[{"name":"contractAddr","type":"address"},{"name":"user","type":"address"}],"name":"grantWrite","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
--         'function', 1, now(), now());

-- TODO 与v143-v150中重复
-- INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
-- VALUES ('0x99c26010', 0,
--         '{"constant":false,"inputs":[{"name":"contractAddr","type":"address"},{"name":"user","type":"address"}],"name":"revokeWrite","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
--         'function', 1, now(), now());
-- (contract life cycle 0x1007)
-- getStatus unfreeze freeze grantManager queryManager revokeManager
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x30ccebb5', 0,
        '{"constant":true,"inputs":[{"name":"addr","type":"address"}],"name":"getStatus","outputs":[{"name":"","type":"uint256"},{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x45c8b1a6', 0,
        '{"constant":false,"inputs":[{"name":"addr","type":"address"}],"name":"unfreeze","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x8d1fdf2f', 0,
        '{"constant":false,"inputs":[{"name":"addr","type":"address"}],"name":"freeze","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xa721fb43', 0,
        '{"constant":false,"inputs":[{"name":"contractAddr","type":"address"},{"name":"userAddr","type":"address"}],"name":"grantManager","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xbc92a700', 0,
        '{"constant":true,"inputs":[{"name":"addr","type":"address"}],"name":"queryManager","outputs":[{"name":"","type":"uint256"},{"name":"","type":"address[]"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());

-- TODO 与v143-v150中重复
-- INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
-- VALUES ('0x3a67288f', 0,
--         '{"constant":false,"inputs":[{"name":"contractAddr","type":"address"},{"name":"userAddr","type":"address"}],"name":"revokeManager","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
--         'function', 1, now(), now());
-- (chain governance 0x1008)
-- listOperators updateCommitteeMemberWeight queryThreshold queryCommitteeMemberWeight grantCommitteeMember
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x039a93ca', 0,
        '{"constant":true,"inputs":[],"name":"listOperators","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x246c3376', 0,
        '{"constant":false,"inputs":[{"name":"user","type":"address"},{"name":"weight","type":"int256"}],"name":"updateCommitteeMemberWeight","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x281af27d', 0,
        '{"constant":true,"inputs":[],"name":"queryThreshold","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x6c147119', 0,
        '{"constant":true,"inputs":[{"name":"user","type":"address"}],"name":"queryCommitteeMemberWeight","outputs":[{"name":"","type":"bool"},{"name":"","type":"int256"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x6f8f521f', 0,
        '{"constant":false,"inputs":[{"name":"user","type":"address"}],"name":"grantCommitteeMember","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
-- unfreezeAccount listCommitteeMembers updateThreshold revokeCommitteeMember grantOperator
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x788649ea', 0,
        '{"constant":false,"inputs":[{"name":"account","type":"address"}],"name":"unfreezeAccount","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x885a3a72', 0,
        '{"constant":true,"inputs":[],"name":"listCommitteeMembers","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x97b00861', 0,
        '{"constant":false,"inputs":[{"name":"threshold","type":"int256"}],"name":"updateThreshold","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xcafb4d1b', 0,
        '{"constant":false,"inputs":[{"name":"user","type":"address"}],"name":"revokeCommitteeMember","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xe348da13', 0,
        '{"constant":false,"inputs":[{"name":"user","type":"address"}],"name":"grantOperator","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
-- freezeAccount revokeOperator getAccountStatus
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xf26c159f', 0,
        '{"constant":false,"inputs":[{"name":"account","type":"address"}],"name":"freezeAccount","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xfad8b32a', 0,
        '{"constant":false,"inputs":[{"name":"user","type":"address"}],"name":"revokeOperator","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xfd4fa05a', 0,
        '{"constant":true,"inputs":[{"name":"account","type":"address"}],"name":"getAccountStatus","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());

-- ----------------------------
-- 4、init tb_method of guomi encrypt type (repeated methodId is removed, ex: remove(string))
-- ----------------------------
-- (system config info 0x1000) setValueByKey
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x0749b518', 0,
        '{"constant":false,"inputs":[{"name":"key","type":"string"},{"name":"value","type":"string"}],"name":"setValueByKey","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
-- (table factory 0x1001) createTable openTable
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xc92a7801', 0,
        '{"constant":false,"inputs":[{"name":"tableName","type":"string"},{"name":"key","type":"string"},{"name":"valueField","type":"string"}],"name":"createTable","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());

-- TODO 与v143-v150中重复
-- INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
-- VALUES ('0x59a48b65', 0,
--         '{"constant":true,"inputs":[{"name":"","type":"string"}],"name":"openTable","outputs":[{"name":"","type":"address"}],"payable":false,"stateMutability":"view","type":"function"}',
--         'function', 1, now(), now());
-- (crud info 0x1002) update select remove insert(same as cns's insert)
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x10bd675b', 0,
        '{"constant":false,"inputs":[{"name":"tableName","type":"string"},{"name":"key","type":"string"},{"name":"entry","type":"string"},{"name":"condition","type":"string"},{"name":"optional","type":"string"}],"name":"update","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x7388111f', 0,
        '{"constant":true,"inputs":[{"name":"tableName","type":"string"},{"name":"key","type":"string"},{"name":"condition","type":"string"},{"name":"optional","type":"string"}],"name":"select","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x81b81824', 0,
        '{"constant":false,"inputs":[{"name":"tableName","type":"string"},{"name":"key","type":"string"},{"name":"condition","type":"string"},{"name":"optional","type":"string"}],"name":"remove","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xb8eaa08d', 0,
        '{"constant":false,"inputs":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"addr","type":"string"},{"name":"abi","type":"string"}],"name":"insert","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
-- (consensus info node manage 0x1003) addObserver addSealer remove
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x25e85d16', 0,
        '{"constant":false,"inputs":[{"name":"nodeID","type":"string"}],"name":"addObserver","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xdf434acc', 0,
        '{"constant":false,"inputs":[{"name":"nodeID","type":"string"}],"name":"addSealer","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x86b733f9', 0,
        '{"constant":false,"inputs":[{"name":"nodeID","type":"string"}],"name":"remove","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
-- (cns info 0x1004) selectByName selectByNameAndVersion // insert(ignored, same as crud's insert method: insert(string,string,string,string)
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x078af4af', 0,
        '{"constant":true,"inputs":[{"name":"name","type":"string"}],"name":"selectByName","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xec72a422', 0,
        '{"constant":true,"inputs":[{"name":"name","type":"string"},{"name":"version","type":"string"}],"name":"selectByNameAndVersion","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
-- INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time) VALUES ('0xb8eaa08d', 0, '{"constant":false,"inputs":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"addr","type":"string"},{"name":"abi","type":"string"}],"name":"insert","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}', 'function', 1, now(), now());
-- (permission manage 0x1005) insert queryByName remove grantWrite revokeWrite
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xce0a9fb9', 0,
        '{"constant":false,"inputs":[{"name":"table_name","type":"string"},{"name":"addr","type":"string"}],"name":"insert","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xbbec3f91', 0,
        '{"constant":true,"inputs":[{"name":"table_name","type":"string"}],"name":"queryByName","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x85d23afc', 0,
        '{"constant":false,"inputs":[{"name":"table_name","type":"string"},{"name":"addr","type":"string"}],"name":"remove","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());

-- TODO 与v143-v150中重复
-- INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
-- VALUES ('0xd010d23c', 0,
--         '{"constant":false,"inputs":[{"name":"contractAddr","type":"address"},{"name":"user","type":"address"}],"name":"grantWrite","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
--         'function', 1, now(), now());

-- TODO 与v143-v150中重复
-- INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
-- VALUES ('0xdf12fe78', 0,
--         '{"constant":false,"inputs":[{"name":"contractAddr","type":"address"},{"name":"user","type":"address"}],"name":"revokeWrite","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
--         'function', 1, now(), now());
-- (contract life cycle 0x1007)
-- getStatus unfreeze freeze grantManager queryManager revokeManager
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xbca14431', 0,
        '{"constant":true,"inputs":[{"name":"addr","type":"address"}],"name":"getStatus","outputs":[{"name":"","type":"uint256"},{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x61cb24c3', 0,
        '{"constant":false,"inputs":[{"name":"addr","type":"address"}],"name":"unfreeze","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xf12c66df', 0,
        '{"constant":false,"inputs":[{"name":"addr","type":"address"}],"name":"freeze","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x27c46414', 0,
        '{"constant":false,"inputs":[{"name":"contractAddr","type":"address"},{"name":"userAddr","type":"address"}],"name":"grantManager","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xa450e730', 0,
        '{"constant":true,"inputs":[{"name":"addr","type":"address"}],"name":"queryManager","outputs":[{"name":"","type":"uint256"},{"name":"","type":"address[]"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());

-- TODO 与v143-v150中重复
-- INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
-- VALUES ('0x00c77684', 0,
--         '{"constant":false,"inputs":[{"name":"contractAddr","type":"address"},{"name":"userAddr","type":"address"}],"name":"revokeManager","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
--         'function', 1, now(), now());
-- (chain governance 0x1008)
-- listOperators updateCommitteeMemberWeight queryThreshold queryCommitteeMemberWeight grantCommitteeMember
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xb90059a3', 0,
        '{"constant":true,"inputs":[],"name":"listOperators","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x95e96f8f', 0,
        '{"constant":false,"inputs":[{"name":"user","type":"address"},{"name":"weight","type":"int256"}],"name":"updateCommitteeMemberWeight","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x35365efb', 0,
        '{"constant":true,"inputs":[],"name":"queryThreshold","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xc784c982', 0,
        '{"constant":true,"inputs":[{"name":"user","type":"address"}],"name":"queryCommitteeMemberWeight","outputs":[{"name":"","type":"bool"},{"name":"","type":"int256"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xcbff0346', 0,
        '{"constant":false,"inputs":[{"name":"user","type":"address"}],"name":"grantCommitteeMember","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
-- unfreezeAccount listCommitteeMembers updateThreshold revokeCommitteeMember grantOperator
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x2312386d', 0,
        '{"constant":false,"inputs":[{"name":"account","type":"address"}],"name":"unfreezeAccount","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x77cb0994', 0,
        '{"constant":true,"inputs":[],"name":"listCommitteeMembers","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x931af204', 0,
        '{"constant":false,"inputs":[{"name":"threshold","type":"int256"}],"name":"updateThreshold","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x681362f3', 0,
        '{"constant":false,"inputs":[{"name":"user","type":"address"}],"name":"revokeCommitteeMember","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xd1db6540', 0,
        '{"constant":false,"inputs":[{"name":"user","type":"address"}],"name":"grantOperator","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
-- freezeAccount revokeOperator getAccountStatus
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0x563e46a5', 0,
        '{"constant":false,"inputs":[{"name":"account","type":"address"}],"name":"freezeAccount","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xc9ab2069', 0,
        '{"constant":false,"inputs":[{"name":"user","type":"address"}],"name":"revokeOperator","outputs":[{"name":"","type":"int256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}',
        'function', 1, now(), now());
INSERT INTO tb_method(method_id, group_id, abi_info, method_type, contract_type, create_time, modify_time)
VALUES ('0xa41e61cc', 0,
        '{"constant":true,"inputs":[{"name":"account","type":"address"}],"name":"getAccountStatus","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"}',
        'function', 1, now(), now());


-- ----------------------------
-- 5、init tb_alert_rule
-- ----------------------------
-- add node status alert rule template
INSERT INTO tb_alert_rule(rule_name, enable, alert_type, alert_level, alert_interval_seconds, alert_content,
                          content_param_list, create_time, modify_time)
VALUES ('节点异常告警/Node Exception', 0, 1, 1, 3600,
        '{nodeId}节点异常，请到“节点管理”页面查看具体信息 / Node: {nodeIdEn} node status exception，please check out in \"Node Management\"',
        '[\"{nodeId}\", \"{nodeIdEn}\"]', now(), now());
-- add audit alert rule template
INSERT INTO tb_alert_rule(rule_name, enable, alert_type, alert_level, alert_interval_seconds, alert_content,
                          content_param_list, create_time, modify_time)
VALUES ('审计异常告警/Audit Exception', 0, 2, 1, 3600,
        '审计异常：{auditType}，请到“交易审计”页面查看具体信息 / Audit alert: {auditTypeEn}，please check out in "Transaction Audit"',
        '["{auditType}", "{auditTypeEn}"]', now(), now());
-- add cert alert rule template
INSERT INTO tb_alert_rule(rule_name, enable, alert_type, alert_level, alert_interval_seconds, alert_content,
                          content_param_list, create_time, modify_time)
VALUES ('证书有效期告警/Cert Validity Exception', 0, 3, 1, 3600,
        '证书将在{time}过期，请到“证书管理”页面查看具体信息 / Cert validity exception：invalid at {timeEn}，please check out in "Cert Management"',
        '["{time}", "{timeEn}"]', now(), now());


-- ----------------------------
-- 6、init tb_mail_server_config
-- ----------------------------
-- add mail_server_config template
INSERT INTO tb_mail_server_config(server_name, host, port, username, password, protocol, default_encoding, create_time,
                                  modify_time, authentication, starttls_enable, starttls_required, socket_factory_port,
                                  socket_factory_class, socket_factory_fallback, enable)
VALUES ('Default config', 'smtp.qq.com', '25', 'yourmail@qq.com', 'yourpassword', 'smtp', 'UTF-8', now(), now(), 1, 1,
        0, 465, 'javax.net.ssl.SSLSocketFactory', 0, 0);


-- ----------------------------
-- 7、init tb_config
-- ----------------------------
INSERT INTO tb_config(config_name, config_type, config_value, create_time, modify_time)
VALUES ('docker 镜像版本', 1, 'v2.9.1', now(), now());


-- ----------------------------
-- 8、init tb_app_info data (template)
-- ----------------------------
-- TODO 与v143-v150中重复
-- INSERT INTO tb_app_info (app_name, app_key, app_type, app_doc_link, app_icon, app_desc, app_detail, create_time,
--                          modify_time)
-- VALUES ('WeId-temp', 'app00001', 1, 'https://weidentity.readthedocs.io/zh_CN/latest/docs/deploy-via-web.html',
--         'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAFAAAABQCAYAAACOEfKtAAAACXBIWXMAAAsTAAALEwEAmpwYAAAFGmlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNi4wLWMwMDIgNzkuMTY0MzUyLCAyMDIwLzAxLzMwLTE1OjUwOjM4ICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIgeG1sbnM6cGhvdG9zaG9wPSJodHRwOi8vbnMuYWRvYmUuY29tL3Bob3Rvc2hvcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RFdnQ9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZUV2ZW50IyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgMjEuMSAoTWFjaW50b3NoKSIgeG1wOkNyZWF0ZURhdGU9IjIwMjEtMDMtMThUMTY6NTc6MzQrMDg6MDAiIHhtcDpNb2RpZnlEYXRlPSIyMDIxLTAzLTE4VDE4OjAyOjAxKzA4OjAwIiB4bXA6TWV0YWRhdGFEYXRlPSIyMDIxLTAzLTE4VDE4OjAyOjAxKzA4OjAwIiBkYzpmb3JtYXQ9ImltYWdlL3BuZyIgcGhvdG9zaG9wOkNvbG9yTW9kZT0iMyIgcGhvdG9zaG9wOklDQ1Byb2ZpbGU9InNSR0IgSUVDNjE5NjYtMi4xIiB4bXBNTTpJbnN0YW5jZUlEPSJ4bXAuaWlkOjg1NDJjNjJlLTZjYTUt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',
--         'WeIdentity是一套分布式多中心的技术解决方案。',
--         'WeIdentity目前主要包含两大模块：WeIdentity DID以及WeIdentity Credential。 WeIdentity DID模块在FISCO-BCOS区块链底层平台上实现了一套符合W3C DID规范的分布式多中心的身份标识协议，使实体（人或物）的现实身份实现了链上的身份标识；WeIdentity Credential提供了一整套基于W3C VC规范的解决方案，旨在对这一类数据进行标准化、电子化，生成可验证、可交换的「凭证」（Credential），支持对凭证的属性进行选择性披露，及生成链上存证（Evidence）。',
--         now(), now());
