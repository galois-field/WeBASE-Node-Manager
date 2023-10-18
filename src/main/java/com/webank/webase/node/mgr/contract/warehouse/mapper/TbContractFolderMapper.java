package com.webank.webase.node.mgr.contract.warehouse.mapper;

import com.webank.webase.node.mgr.contract.warehouse.entity.TbContractFolder;
import com.webank.webase.node.mgr.contract.warehouse.entity.TbWarehouse;
import java.util.List;
import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.InsertProvider;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Result;
import org.apache.ibatis.annotations.Results;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.SelectKey;
import org.apache.ibatis.annotations.UpdateProvider;
import org.apache.ibatis.type.JdbcType;

/**
 * @author marsli
 */
public interface TbContractFolderMapper {

    @Select({ "select id,folder_name,create_time,modify_time,warehouse_id,description,description_en,folder_detail,folder_detail_en from tb_contract_folder" })
    List<TbContractFolder> findAll();

    @Select({ "select id,folder_name,create_time,modify_time,warehouse_id,description,description_en,folder_detail,folder_detail_en from tb_contract_folder where warehouse_id = #{warehouseId} order by id" })
    List<TbContractFolder> findByWarehouseId(@Param("warehouseId") Integer warehouseId);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table tb_contract_folder
     *
     * @mbg.generated
     */
    @Delete({ "delete from tb_contract_folder where id = #{id,jdbcType=INTEGER}" })
    int deleteByPrimaryKey(@Param("id") Integer id);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table tb_contract_folder
     *
     * @mbg.generated
     */
    @InsertProvider(type = TbContractFolderSqlProvider.class, method = "insertSelective")
    @SelectKey(statement = "SELECT currval('tb_contract_folder_id_seq')", keyProperty = "id", before = false, resultType = Integer.class)
    int insertSelective(TbContractFolder record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table tb_contract_folder
     *
     * @mbg.generated
     */
    @Select({ "select id, folder_name, create_time, modify_time, warehouse_id, description, description_en, folder_detail, folder_detail_en from tb_contract_folder where id = #{id,jdbcType=INTEGER}" })
    @Results({ @Result(column = "id", property = "id", jdbcType = JdbcType.INTEGER, id = true), @Result(column = "folder_name", property = "folderName", jdbcType = JdbcType.VARCHAR), @Result(column = "create_time", property = "createTime", jdbcType = JdbcType.TIMESTAMP), @Result(column = "modify_time", property = "modifyTime", jdbcType = JdbcType.TIMESTAMP), @Result(column = "warehouse_id", property = "warehouseId", jdbcType = JdbcType.INTEGER), @Result(column = "description", property = "description", jdbcType = JdbcType.LONGVARCHAR), @Result(column = "description_en", property = "descriptionEn", jdbcType = JdbcType.LONGVARCHAR), @Result(column = "folder_detail", property = "folderDetail", jdbcType = JdbcType.LONGVARCHAR), @Result(column = "folder_detail_en", property = "folderDetailEn", jdbcType = JdbcType.LONGVARCHAR) })
    TbContractFolder selectByPrimaryKey(Integer id);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table tb_contract_folder
     *
     * @mbg.generated
     */
    @UpdateProvider(type = TbContractFolderSqlProvider.class, method = "updateByPrimaryKeySelective")
    int updateByPrimaryKeySelective(TbContractFolder record);

    /**
     * This method was generated by MyBatis Generator.
     * This method corresponds to the database table tb_contract_folder
     *
     * @mbg.generated
     */
    @Insert({"insert into tb_contract_folder (id, folder_name, create_time, modify_time,warehouse_id, description,description_en, folder_detail,folder_detail_en) values(#{detail.id, jdbcType=INTEGER}, #{detail.folderName, jdbcType=VARCHAR}, #{detail.createTime, jdbcType=TIMESTAMP}, #{detail.modifyTime, jdbcType=TIMESTAMP}, #{detail.warehouseId, jdbcType=INTEGER}, #{detail.description, jdbcType=LONGVARCHAR}, #{detail.descriptionEn, jdbcType=LONGVARCHAR}, #{detail.folderDetail, jdbcType=LONGVARCHAR}, #{detail.folderDetailEn, jdbcType=LONGVARCHAR})"})
    int batchInsert(@Param("detail") TbContractFolder detail);
}
