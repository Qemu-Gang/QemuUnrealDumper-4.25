#include "fmt/core.h"
#include "utils.h"
#include "wrappers.h"
#include "memory.h"

#include "sigscanner.h"
#include "memflow_win32.h"


#include <filesystem>
#include <iostream>
namespace fs = std::filesystem;

enum {
    SUCCESS,
    FAILED,
    MEMFLOW_INIT_FAILURE,
    WINDOW_NOT_FOUND,
    PROCESS_NOT_FOUND,
    READER_ERROR,
    CANNOT_GET_PROCNAME,
    ENGINE_ERROR,
    MODULE_NOT_FOUND,
    CANNOT_READ,
    INVALID_IMAGE,
    NAMES_NOT_FOUND,
    OBJECTS_NOT_FOUND,
    FILE_NOT_OPEN,
    ZERO_PACKAGES
};

class Dumper
{
protected:
    bool Full = true;
    bool Wait = false;
    fs::path Directory;
    //memflow vars
    uint32_t                pid = 0;
    Kernel                  *kernel = 0;
    Win32Process            *game = 0;
    Win32ModuleInfo         *module = 0;
    Win32ProcessInfo        *procInfo = 0;
    OsProcessInfoObj        *osProcInfo = 0;
    OsProcessModuleInfoObj  *osModuleInfo = 0;
    Address                 moduleBase;
    Address                 moduleSize;
    VirtualMemoryObj        *mem = 0;
    ConnectorInventory      *inv = 0;
    CloneablePhysicalMemoryObj *conn = 0;
    char gameName[64];
private:
    Dumper() {};
    bool FindObjObjects()
    {
        //static std::vector<byte> sigv[] = { { 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x63, 0x8C, 0x24, 0xE0 },
        //                                    { 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x0C, 0xC8, 0x48, 0x8D, 0x04, 0xD1, 0xEB},
        //                                    { 0x48 , 0x8b , 0x0d , 0x00 , 0x00 , 0x00 , 0x00 , 0x81 , 0x4c , 0xd1 , 0x08 , 0x00 , 0x00 , 0x00 , 0x40},
        //                                    { 0x48, 0x8d, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x39, 0x44, 0x24, 0x68} };
        //for (auto& sig : sigv)
        //{
        //    auto address = FindPointer(start, end, sig.data(), sig.size());
        //    if (!address) continue;
        //    ObjObjects = *reinterpret_cast<decltype(ObjObjects)*>(address);
        //    return true;
        //}

        static const char *sigs[] = {
                "48 8B 05 ? ? ? ? 48 63 8C 24 E0",
                "48 8B 05 ? ? ? ? 48 8B 0C C8 48 8D 04 D1 EB",
                "48 8B 0D ? ? ? ? 81 4C D1 08 ? ? ? 40",
                "48 8D 1D ? ? ? ? 39 44 24 68"
        };
        for( const char *sig : sigs )
        {
            Address line = FindPatternInMemory( mem, sig, moduleBase, moduleSize );
            if( !line )
                continue;
            virt_read_raw_into( mem, GetAbsoluteAddressVm( mem, line, 3, 7 ), (uint8_t*)&ObjObjects, sizeof(TUObjectArray) );
            return true;
        }
        return false;
    }
    bool FindNamePoolData()
    {
        //static std::vector<byte> sigv[] = { {0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xE9, 0x73, 0xAB, 0xFF, 0xFF},
        //                                    { 0x48, 0x8d, 0x35, 0x00, 0x00, 0x00, 0x00, 0xeb, 0x16 } };
        //for (auto& sig : sigv)
        //{
        //    auto address = FindPointer(start, end, sig.data(), sig.size());
        //    if (!address) continue;
        //    NamePoolData = *reinterpret_cast<decltype(NamePoolData)*>(address);
        //    return true;
        //}

        static const char *sigs[] = {
                "48 8D 0D ? ? ? ? E9 73 AB FF FF",
                "48 8D 35 ? ? ? ? EB 16"
        };
        for( const char *sig : sigs )
        {
            Address line = FindPatternInMemory( mem, sig, moduleBase, moduleSize );
            if( !line )
                continue;
            virt_read_raw_into( mem, GetAbsoluteAddressVm( mem, line, 3, 7 ), (uint8_t*)&NamePoolData, sizeof(FNamePool) );
            return true;
        }
        return false;
    }
    bool InitMemflow()
    {
        inv = inventory_scan();
        conn = inventory_create_connector(inv, "qemu_procfs", "");
        if (!inv || !conn)
        {
            printf("Couldn't open conn!\n");
            inventory_free(inv);
            return false;
        }

        kernel = kernel_build(conn);
        if( !kernel )
        {
            printf("kernel error\n");
            connector_free(conn);
            inventory_free(inv);
            return false;
        }

        game = kernel_into_process_pid( kernel, pid );
        if( !game )
        {
            printf("Couldn't find the game from pid - (%d)\n", pid );
            kernel_free(kernel);
            inventory_free(inv);
            connector_free(conn);
            return false;
        }
        //NOTE: Here we assume the module wanted is the same as the game .exe - Change here if you want a .dll
        module = process_main_module_info( game );
        if( !module )
        {
            printf("Couldn't find module for the game!\n");
            process_free(game);
            kernel_free(kernel);
            inventory_free(inv);
            connector_free(conn);
            return false;
        }
        osModuleInfo = module_info_trait(module);
        moduleBase = os_process_module_base(osModuleInfo);
        moduleSize = os_process_module_size(osModuleInfo);
        mem = process_virt_mem(game);

        return true;
    }
public:
    static Dumper* GetInstance() 
    {
        static Dumper dumper;
        return &dumper;
    }
    int Init(int argc, char* argv[]) 
    {
        for (auto i = 1; i < argc; i++)
        {
            auto arg = argv[i];
            if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) { printf(" Usage: UnrealDumper <pid>\n'-p' - dump only names and objects\n'-w' - wait for input (it gives me time to inject mods)\n"); return FAILED; }
            else if (!strcmp(arg, "-p")) { Full = false; }
            else if (!strcmp(arg, "-w")) { Wait = true; }
            else
            {
                // assume it's the pid
                pid = atoi( arg );
            }
        }

        printf("Target pid(%d)\n", pid);

        if (Wait) { std::cin.get(); }

        if ( !InitMemflow() ) { return MEMFLOW_INIT_FAILURE; }
        if ( !ReaderInit( mem ) ) { return READER_ERROR; };

        fs::path processName;
        char tempName[256];
        os_process_module_name( osModuleInfo, tempName, 256 );
        printf("Found UE4 game: %s\n", tempName);

        processName = tempName;


        if( processName.empty() )
            return CANNOT_GET_PROCNAME;


        auto root = fs::path(argv[0]); root.remove_filename();
        auto game = processName.stem();
        Directory = root / "Games" / game;
        fs::create_directories(Directory);
        if (!EngineInit(game.string())) { return ENGINE_ERROR; };

        Base = moduleBase; //hacky - used in wrappers.cpp

        if( !FindObjObjects() )
            return OBJECTS_NOT_FOUND;
        if( !FindNamePoolData() )
            return NAMES_NOT_FOUND;

        return SUCCESS;
    }
    int Dump() 
    {
        /*
        * Names dumping.
        * We go through each block, except last, that is not fully filled.
        * In each block we calculate next entry depending on previous entry size.
        */
        {
            File file(Directory / "NamesDump.txt", "w");
            if (!file) { return FILE_NOT_OPEN; }
            size_t size = 0;
            NamePoolData.Dump([&file, &size](std::string_view name, uint32_t id) { fmt::print(file, "[{:0>6}] {}\n", id, name); size++; });
            fmt::print("Names: {}\n", size);
        }
        {
            // Why we need to iterate all objects twice? We dumping objects and filling packages simultaneously.
            std::unordered_map<byte*, std::vector<UE_UObject>> packages;
            {
                File file(Directory / "ObjectsDump.txt", "w");
                if (!file) { return FILE_NOT_OPEN; }
                size_t size = 0;
                if (Full)
                {
                    ObjObjects.Dump(
                        [&file, &size, &packages](UE_UObject object)
                        {
                            fmt::print(file, "[{:0>6}] <{}> {}\n", object.GetIndex(), object.GetAddress(), object.GetFullName()); size++;
                            if (object.IsA<UE_UStruct>() || object.IsA<UE_UEnum>())
                            {
                                auto packageObj = object.GetPackageObject();
                                packages[packageObj].push_back(object);
                            }
                        }
                    );
                }
                else
                {
                    ObjObjects.Dump(
                            [&file, &size](UE_UObject object) { fmt::print(file, "[{:0>6}] <{}> {}\n", object.GetIndex(), object.GetAddress(), object.GetFullName()); size++; }
                    );
                }

                fmt::print("Objects: {}\n", size);
            }

            if (!Full) { return SUCCESS; }

            {
                // Clearing all packages with small amount of objects (comment this if you need all packages to be dumped)
                size_t size = packages.size();
                size_t erased = std::erase_if(packages, [](std::pair<byte* const, std::vector<UE_UObject>>& package) { return package.second.size() < 2; });

                fmt::print("Wiped {} out of {}\n", erased, size);
            }

            // Checking if we have any package after clearing.
            if (!packages.size()) { return ZERO_PACKAGES; }

            fmt::print("Packages: {}\n", packages.size());

            {
                auto path = Directory / "DUMP";
                fs::create_directories(path);

                int i = 1; int saved = 0;
                std::string unsaved{};

                for (UE_UPackage package : packages)
                {
                    fmt::print("\rProcessing: {}/{}", i++, packages.size());

                    package.Process();
                    if (package.Save(path)) { saved++; }
                    else { unsaved += (package.GetObject().GetName() + ", "); };
                }

                fmt::print("\nSaved packages: {}", saved);

                if (unsaved.size())
                {
                    unsaved.erase(unsaved.size() - 2);
                    fmt::print("\nUnsaved packages (empty classes): [ {} ]", unsaved);
                }

            }
        }
        return SUCCESS;
    }
};

int main(int argc, char* argv[])
{
    auto dumper = Dumper::GetInstance();

    switch (dumper->Init(argc, argv))
    {
    case MEMFLOW_INIT_FAILURE: { puts("memflow init failure!"); return FAILED; }
    case WINDOW_NOT_FOUND: { puts("Can't find UE4 window"); return FAILED; }
    case PROCESS_NOT_FOUND: { puts("Can't find process"); return FAILED; }
    case READER_ERROR: { puts("Can't init reader"); return FAILED; }
    case CANNOT_GET_PROCNAME: { puts("Can't get process name"); return FAILED; }
    case ENGINE_ERROR: { puts("Can't find offsets for this game"); return FAILED; }
    case MODULE_NOT_FOUND: { puts("Can't enumerate modules (protected process?)"); return FAILED; }
    case CANNOT_READ: { puts("Can't read process memory"); return FAILED; }
    case INVALID_IMAGE: { puts("Can't get executable sections"); return FAILED; }
    case OBJECTS_NOT_FOUND: { puts("Can't find objects array"); return FAILED; }
    case NAMES_NOT_FOUND: { puts("Can't find names array"); return FAILED; }
    case SUCCESS: { break; };
    default: { return FAILED; }
    }

    switch (dumper->Dump())
    {
    case FILE_NOT_OPEN: { puts("Can't open file"); return FAILED; }
    case ZERO_PACKAGES: { puts("Size of packages is zero"); return FAILED; }
    case SUCCESS: { break; }
    default: { return FAILED; }
    }

    return SUCCESS;
}