/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#pragma once

#include "application.h"

namespace falco {
namespace app {

// action derives from base_action and additionally saves a reference
// to an application object. The reason for the subclass is to allow
// for unit tests for the action manager without having to bring in
// all of the falco application code (outputs, engine rule loading,
// etc.) into the unit tests.
struct action : public base_action {
	action(const char *name,
	       const char *group,
	       std::list<std::string> &prerequsites,
	       action_run_f run_f,
	       action_deinit_f deinit_f,
	       application &app)
		: falco::app::base_action(name, group,
					  prerequsites,
					  run_f, deinit_f),
		app(app) {};

	application &app;
};

// Each file in app_actions/ exports an function to return an action
extern std::shared_ptr<base_action> act_create_signal_handlers(application &app);
extern std::shared_ptr<base_action> act_daemonize(application &app);
extern std::shared_ptr<base_action> act_init_falco_engine(application &app);
extern std::shared_ptr<base_action> act_init_inspector(application &app);
extern std::shared_ptr<base_action> act_init_outputs(application &app);
extern std::shared_ptr<base_action> act_list_fields(application &app);
extern std::shared_ptr<base_action> act_list_plugins(application &app);
extern std::shared_ptr<base_action> act_load_config(application &app);
extern std::shared_ptr<base_action> act_load_plugins(application &app);
extern std::shared_ptr<base_action> act_load_rules_files(application &app);
extern std::shared_ptr<base_action> act_print_help(application &app);
extern std::shared_ptr<base_action> act_print_ignored_events(application &app);
extern std::shared_ptr<base_action> act_print_support(application &app);
extern std::shared_ptr<base_action> act_print_version(application &app);
#ifndef MINIMAL_BUILD
extern std::shared_ptr<base_action> act_start_grpc_server(application &app);
extern std::shared_ptr<base_action> act_start_webserver(application &app);
#endif
extern std::shared_ptr<base_action> act_validate_rules_files(application &app);
extern std::shared_ptr<base_action> act_open_inspector(application &app);
extern std::shared_ptr<base_action> act_process_events(application &app);

}; // namespace app
}; // namespace falco


