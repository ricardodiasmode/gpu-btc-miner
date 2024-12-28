# Install script for directory: C:/Users/ricar/source/repos/btc-miner/vcpkg_installed/vcpkg/blds/boost-date-time/src/ost-1.85.0-ee5b51880c.clean

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "C:/Users/ricar/source/repos/btc-miner/vcpkg_installed/vcpkg/pkgs/boost-date-time_x64-windows")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "OFF")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for the subdirectory.
  include("C:/Users/ricar/source/repos/btc-miner/vcpkg_installed/vcpkg/blds/boost-date-time/x64-windows-rel/libs/date_time/cmake_install.cmake")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE DIRECTORY FILES "C:/Users/ricar/source/repos/btc-miner/vcpkg_installed/vcpkg/blds/boost-date-time/src/ost-1.85.0-ee5b51880c.clean/libs/date_time/include/")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY OPTIONAL FILES "C:/Users/ricar/source/repos/btc-miner/vcpkg_installed/vcpkg/blds/boost-date-time/x64-windows-rel/stage/lib/boost_date_time-vc144-mt-x64-1_85.lib")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE SHARED_LIBRARY FILES "C:/Users/ricar/source/repos/btc-miner/vcpkg_installed/vcpkg/blds/boost-date-time/x64-windows-rel/stage/bin/boost_date_time-vc144-mt-x64-1_85.dll")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/bin" TYPE FILE OPTIONAL FILES "C:/Users/ricar/source/repos/btc-miner/vcpkg_installed/vcpkg/blds/boost-date-time/x64-windows-rel/stage/bin/boost_date_time-vc144-mt-x64-1_85.pdb")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/boost_date_time-1.85.0/boost_date_time-targets.cmake")
    file(DIFFERENT _cmake_export_file_changed FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/boost_date_time-1.85.0/boost_date_time-targets.cmake"
         "C:/Users/ricar/source/repos/btc-miner/vcpkg_installed/vcpkg/blds/boost-date-time/x64-windows-rel/CMakeFiles/Export/d48b9d79dd03c2415a6aa6b76fa00bf6/boost_date_time-targets.cmake")
    if(_cmake_export_file_changed)
      file(GLOB _cmake_old_config_files "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/boost_date_time-1.85.0/boost_date_time-targets-*.cmake")
      if(_cmake_old_config_files)
        string(REPLACE ";" ", " _cmake_old_config_files_text "${_cmake_old_config_files}")
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/boost_date_time-1.85.0/boost_date_time-targets.cmake\" will be replaced.  Removing files [${_cmake_old_config_files_text}].")
        unset(_cmake_old_config_files_text)
        file(REMOVE ${_cmake_old_config_files})
      endif()
      unset(_cmake_old_config_files)
    endif()
    unset(_cmake_export_file_changed)
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/boost_date_time-1.85.0" TYPE FILE FILES "C:/Users/ricar/source/repos/btc-miner/vcpkg_installed/vcpkg/blds/boost-date-time/x64-windows-rel/CMakeFiles/Export/d48b9d79dd03c2415a6aa6b76fa00bf6/boost_date_time-targets.cmake")
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/boost_date_time-1.85.0" TYPE FILE FILES "C:/Users/ricar/source/repos/btc-miner/vcpkg_installed/vcpkg/blds/boost-date-time/x64-windows-rel/CMakeFiles/Export/d48b9d79dd03c2415a6aa6b76fa00bf6/boost_date_time-targets-release.cmake")
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/boost_date_time-1.85.0" TYPE FILE FILES "C:/Users/ricar/source/repos/btc-miner/vcpkg_installed/vcpkg/blds/boost-date-time/x64-windows-rel/tmpinst/boost_date_time-config.cmake")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/boost_date_time-1.85.0" TYPE FILE FILES "C:/Users/ricar/source/repos/btc-miner/vcpkg_installed/vcpkg/blds/boost-date-time/x64-windows-rel/tmpinst/boost_date_time-config-version.cmake")
endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "C:/Users/ricar/source/repos/btc-miner/vcpkg_installed/vcpkg/blds/boost-date-time/x64-windows-rel/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")