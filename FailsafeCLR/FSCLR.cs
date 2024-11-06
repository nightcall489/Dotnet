using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace bootstrap
{
   public struct MEMORY_BASIC_INFORMATION
   {
      public IntPtr BaseAddress;
      public IntPtr AllocationBase;
      public AllocationProtectEnum AllocationProtect;
      public IntPtr RegionSize;
      public StateEnum State;
      public AllocationProtectEnum Protect;
      public TypeEnum Type;
   }
   public enum AllocationProtectEnum : uint
   {
      PAGE_EXECUTE = 0x00000010,
      PAGE_EXECUTE_READ = 0x00000020,
      PAGE_EXECUTE_READWRITE = 0x00000040,
      PAGE_EXECUTE_WRITECOPY = 0x00000080,
      PAGE_NOACCESS = 0x00000001,
      PAGE_READONLY = 0x00000002,
      PAGE_READWRITE = 0x00000004,
      PAGE_WRITECOPY = 0x00000008,
      PAGE_GUARD = 0x00000100,
      PAGE_NOCACHE = 0x00000200,
      PAGE_WRITECOMBINE = 0x00000400
   }
   public enum StateEnum : uint
   {
      MEM_COMMIT = 0x1000,
      MEM_FREE = 0x10000,
      MEM_RESERVE = 0x2000
   }
   public enum TypeEnum : uint
   {
      MEM_IMAGE = 0x1000000,
      MEM_MAPPED = 0x40000,
      MEM_PRIVATE = 0x20000
   }

   public static class Program
   {
      [DllImport("kernel32.dll")]
      public static extern IntPtr LoadLibrary(string dllToLoad);
      [DllImport("kernel32.dll")]
      public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);
      [DllImport("kernel32.dll")]
      public static extern bool FreeLibrary(IntPtr hModule);

      [UnmanagedFunctionPointer(CallingConvention.Winapi)]
      private delegate int VirtualQueryEx_t(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
      [UnmanagedFunctionPointer(CallingConvention.Winapi)]
      private delegate bool VirtualProtectEx_t(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);


      static void Main()
      {
         var methods = new List<MethodInfo>(typeof(Environment).GetMethods(
                  BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic
                  ));

         var exitMethod = methods.Find((MethodInfo mi) => mi.Name == "Exit");
         if (exitMethod == null)
         {
            return;
         }

         IntPtr k32Dll = LoadLibrary(@"kernel32.dll");
         if (k32Dll == IntPtr.Zero)
            return;

         IntPtr addrVirtualQuery = GetProcAddress(k32Dll, "VirtualQueryEx");
         IntPtr addrVirtualProtect = GetProcAddress(k32Dll, "VirtualProtectEx");

         VirtualQueryEx_t VirtualQueryEx = (VirtualQueryEx_t)Marshal.GetDelegateForFunctionPointer(addrVirtualQuery,  typeof(VirtualQueryEx_t));
         VirtualProtectEx_t VirtualProtectEx = (VirtualProtectEx_t)Marshal.GetDelegateForFunctionPointer(addrVirtualProtect, typeof(VirtualProtectEx_t));

         RuntimeHelpers.PrepareMethod(exitMethod.MethodHandle);

         var exitMethodPtr = exitMethod.MethodHandle.GetFunctionPointer();

         unsafe
         {
            IntPtr patchTarget = exitMethod.MethodHandle.GetFunctionPointer();

            MEMORY_BASIC_INFORMATION MemBasicInfo;
            if (VirtualQueryEx(
                     (IntPtr)(-1),
                     patchTarget,
                     out MemBasicInfo,
                     (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))
                     ) != 0)
            {
               if (MemBasicInfo.Protect == AllocationProtectEnum.PAGE_EXECUTE_READ)
               {
                  uint flOldProtect;
                  if (VirtualProtectEx((IntPtr)(-1), patchTarget, (UIntPtr)1, (uint)AllocationProtectEnum.PAGE_READWRITE, out flOldProtect)) {
                     *(byte*)patchTarget = 0xc3;

                     VirtualProtectEx((IntPtr)(-1), patchTarget, (UIntPtr)1, flOldProtect, out flOldProtect);
                  }
               }
            }
         }

         FreeLibrary(k32Dll);
      }
   }
}
