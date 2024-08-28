#pragma once

#include <evntrace.h>

#ifndef DBG
#define WPP_PRINT(...)
#define WPP_INIT_TRACING(...)
#define WPP_CLEANUP(...)

#define GENERAL

#else
#define WPP_CHECK_FOR_NULL_STRING

// {EDC00A52-CBB9-490E-89A3-69E3FFF137BA}
#define WPP_CONTROL_GUIDS                                                                                              \
    WPP_DEFINE_CONTROL_GUID(MasterHideCtrlGUID, (EDC00A52, CBB9, 490E, 89A3, 69E3FFF137BA),                            \
                            WPP_DEFINE_BIT(GENERAL) /* bit  0 = 0x00000001 */                                          \
    )

#define WPP_LEVEL_EVENT_LOGGER(level, event) WPP_LEVEL_LOGGER(event)
#define WPP_LEVEL_EVENT_ENABLED(level, event) (WPP_LEVEL_ENABLED(event) && WPP_CONTROL(WPP_BIT_##event).Level >= level)

#define TMH_STRINGIFYX(x) #x
#define TMH_STRINGIFY(x) TMH_STRINGIFYX(x)

#ifdef TMH_FILE
#include TMH_STRINGIFY(TMH_FILE)
#endif
#endif