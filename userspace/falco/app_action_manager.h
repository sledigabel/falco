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

#include <functional>
#include <list>
#include <memory>
#include <map>
#include <string>
#include <vector>

namespace falco {
namespace app {

// The result of running an action.
struct run_result {
	// If true, the action completed successfully.
	bool success;

	// If success==false, details on the error.
	std::string errstr;

	// If true, subsequent actions should be performed. If
	// false, subsequent actions should *not* be performed
	// and falco should tear down/exit.
	bool proceed;
};

// An action has a name, a group, a list of prerequsites, a
// std::function that performs the action, and a std::function that
// cleans up any resources created by the action.
//

// Falco does not use this base_action struct directly. Instead, it
// uses the derived struct action in defined_app_actions.h. This split
// allows for writing unit tests on actions without having to pull in
// the application and all of its dependent code (outputs, engine,
// etc.) in unit tests.

typedef std::function<falco::app::run_result(struct base_action &)> action_run_f;
typedef std::function<bool(struct base_action &, std::string &errstr)> action_deinit_f;

struct base_action {
	// Useful values for actions that have no prerequsites or deinit
	static std::list<std::string> s_no_prerequsites;
	static action_deinit_f s_do_nothing;

	base_action(const char *name,
		    const char *group,
		    std::list<std::string> &prerequsites,
		    action_run_f run_f,
		    action_deinit_f deinit_f);
	std::string name;
	std::string group;
	std::list<std::string> prerequsites;
	action_run_f run_f;
	action_deinit_f deinit_f;
};

// This class manages a set of actions, ensuring that they run in an
// order that honors their prerequsites, groups and their run results.

class action_manager {
public:
	action_manager();
	virtual ~action_manager();

	// Actions are organized into groups. All actions from a
	// given group are run before actions from another group.
	//
	// Example groups are "init", "run", etc.
	//
	// This specifies the order of groups.
	void set_groups(std::list<std::string> &groups);

	void add(std::shared_ptr<base_action> act);

	run_result run();

private:

	typedef std::vector<std::shared_ptr<base_action>> ordered_actions_t;

	void sort_groups();
	run_result run_groups();
	void deinit_groups();

	// Return true if a is less (e.g. a should run before b)
	bool compare_actions(const std::shared_ptr<base_action> &a, const std::shared_ptr<base_action> &b);

	std::list<std::string> m_groups;
	std::map<std::string, std::shared_ptr<base_action>> m_actions;
	std::map<std::string, ordered_actions_t> m_actions_ordered;
};

}; // namespace app
}; // namespace falco
