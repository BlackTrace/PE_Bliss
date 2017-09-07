#include <iostream>
#include <fstream>
#include <pe_bliss.h>
#ifdef PE_BLISS_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

//Пример, показывающий, как считать и получить информацию о Image Config (конфигурация исполняемого файла) PE или PE+
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: pe_config_reader.exe PE_FILE" << std::endl;
		return 0;
	}

	//Открываем файл
	std::ifstream pe_file(argv[1], std::ios::in | std::ios::binary);
	if(!pe_file)
	{
		std::cout << "Cannot open " << argv[1] << std::endl;
		return -1;
	}

	try
	{
		//Создаем экземпляр PE или PE+ класса с помощью фабрики
		pe_base image(pe_factory::create_pe(pe_file));

		std::cout << "Reading PE image config info..." << std::hex << std::showbase << std::endl << std::endl;
		
		//Получаем конфигурацию
		const image_config_info info(get_image_config(image));

		//Выводим данные конфигурации
		//Подробнее о полях - в MSDN
		std::cout << "Size: " << info.get_size() << std::endl
			<< "Timestamp: " << info.get_time_stamp() << std::endl
			<< "major version number: " << info.get_major_version() << std::endl
			<< "minor version number: " << info.get_minor_version() << std::endl
			<< "Global flags clear: " << info.get_global_flags_clear() << std::endl
			<< "Global flags set: " << info.get_global_flags_set() << std::endl
			<< "Critical section default timeout: " << info.get_critical_section_default_timeout() << std::endl
			<< "Decommit free block threshold: " << info.get_decommit_free_block_threshold() << std::endl
			<< "Decommit total free threshold: " << info.get_decommit_total_free_threshold() << std::endl
			<< "VA of lock table prefix: " << info.get_lock_prefix_table_va() << std::endl
			<< "Max allocation size: " << info.get_max_allocation_size() << std::endl
			<< "Virtual memory threshold: " << info.get_virtual_memory_threshold() << std::endl
			<< "Process affinity mask: " << info.get_process_affinity_mask() << std::endl
			<< "Process heap flags: " << info.get_process_heap_flags() << std::endl
			<< "CSDVersion: " << info.get_service_pack_version() << std::endl
			<< "VA of edit list: " << info.get_edit_list_va() << std::endl
			<< "Security cookie VA: " << info.get_security_cookie_va() << std::endl
			<< "VA of the sorted table of RVAs of each valid, unique handler in the image: " << info.get_se_handler_table_va() << std::endl
			<< "the count of unique handlers in the table: " << info.get_se_handler_count() << std::endl
			<< "the pointer of Control Flow Guard Check Function: " << info.get_GuardCFCheckFunctionPointer_va() << std::endl
			<< "the pointer of Control Flow Guard Dispatch Function: " << info.get_GuardCFDispatchFunctionPointer_va() << std::endl
			<< "Control Flow Guard Function Table: " << info.get_GuardCFFunctionTable_va() << std::endl
			<< "the count of the Control Flow Guard Function: " << info.get_GuardCFFunctionCount() << std::endl
			<< std::endl;

		//Выведем адреса SE-хендлеров
		const image_config_info::se_handler_list& se_handlers = info.get_se_handler_rvas();
		for(image_config_info::se_handler_list::const_iterator it = se_handlers.begin(); it != se_handlers.end(); ++it)
			std::cout << "SE Handler: " << (*it) << std::endl;
	}
	catch(const pe_exception& e)
	{
		//Если возникла ошибка
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}
