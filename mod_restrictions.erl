-module(mod_restrictions).

-behavior(gen_mod).

-include("ejabberd.hrl").
%% for http
-include("jlib.hrl").
-include_lib("/usr/src/otp_src_R14B04/lib/stdlib/include/qlc.hrl").
-include("web/ejabberd_http.hrl").
-include("web/ejabberd_web_admin.hrl").

-export([start/2, stop/1, on_filter_packet/1, web_menu_host/2, web_page_host/2]).

%% tables records structure to use in record_info
-record(restrictions_groups, {grp, dest}). %% Group can send message to Destination
-record(restrictions_users, {usr, grp}).

start(_Host, _Opts) ->
	?INFO_MSG("mod_restrictions starting", []),
	mnesia:create_table(restrictions_groups,
            [{disc_copies, [node()]} ,
			{attributes, record_info(fields, restrictions_groups)},
			{type, bag}]),
	mnesia:create_table(restrictions_users,
            [{disc_copies, [node()]} ,
			{attributes, record_info(fields, restrictions_users)},
			{type, bag}]),
%%    mnesia:clear_table(restrictions_users),
	ejabberd_hooks:add(filter_packet, global, ?MODULE, on_filter_packet, 50),
	ejabberd_hooks:add(webadmin_menu_main, ?MODULE, web_menu_host, 50),
	ejabberd_hooks:add(webadmin_page_main, ?MODULE, web_page_host, 50),
	ok.

stop(_Host) ->
	?INFO_MSG("mod_restrictions stopping", []),
	ejabberd_hooks:delete(filter_packet, global, ?MODULE, on_filter_packet, 50),
	ejabberd_hooks:delete(webadmin_menu_main, ?MODULE, web_menu_host, 50),
	ejabberd_hooks:delete(webadmin_page_main, ?MODULE, web_page_host, 50),
	ok.

%% should return "Packet" if message allowed or "drop" otherwise
on_filter_packet(drop) ->
	drop;

on_filter_packet({{jid,FromUsr,FromDomain,_,_,_,_} = From,{jid,ToUsr,ToDomain,_,_,_,_} = To,
	{xmlelement,"message",Attrs,Content}} = Packet) when ((From /= To) and (ToUsr /= []) and (FromUsr /= [])) ->
	case  lists:keymember("body",2,Content) of
		true ->
			Ftemp = fun() ->
				Qvve = qlc:q([allow ||  U <- mnesia:table(restrictions_users),
										G <- mnesia:table(restrictions_groups),
										(U#restrictions_users.usr == FromUsr++"@"++FromDomain) and
										(U#restrictions_users.grp == G#restrictions_groups.grp) and (
											(G#restrictions_groups.dest == "all") or
											(G#restrictions_groups.dest == ToDomain) or
											(G#restrictions_groups.dest == ToUsr++"@"++ToDomain)
										)
							]),
				qlc:eval(Qvve)
			end,
			case mnesia:transaction(Ftemp) of
				{atomic,[]} -> %% deny
					{"type",Type} = lists:keyfind("type", 1, Attrs),
					Res = createDenyMessage(To, From, Type);
				_ -> %% allow
					Res = Packet
			end;
		_ ->
			Res = Packet
	end,
	Res;
on_filter_packet(Packet) ->
	Packet.
	
createDenyMessage(From,To,Type) ->
	if
		Type == "groupchat" ->
			drop;
		true ->
			Message = gen_mod:get_module_opt(To#jid.lserver, ?MODULE, deny_message, false),
			if not (Message == false)->
				Attrs = [{"type",Type},{"id","legal"},{"to",To#jid.user++"@"++To#jid.server++"/"++To#jid.resource},{"from",From#jid.user++"@"++From#jid.server++"/"++From#jid.resource}],
				Els = [{xmlcdata,<<"\n">>},{xmlelement,"body",[],[{xmlcdata,list_to_binary(Message)}]}],
				{From,To,{xmlelement,"message",Attrs,Els}};
			true -> drop
			end
	end.
	
%%####################################### Restriction web interface ##################################

web_menu_host(Acc, Lang) ->
        Acc ++ [{"mod_restrictions", ?T("Restrictions")}] .


%% Restrictions interface

web_page_host(_,
             #request{method = Method,
						q = Query,
						path = ["mod_restrictions"],
						lang = _Lang}) ->
	case Method of
		'POST' -> %% Handle database query
			case lists:keyfind("act", 1, Query) of
				{"act","add_usrgrp"} -> %% add user to group
					{"usr",NewUser} = lists:keyfind("usr", 1, Query),
					{"grp",NewGroup} = lists:keyfind("grp", 1, Query),
					F = fun() ->
						mnesia:write(#restrictions_users{usr=NewUser, grp=NewGroup})
					end,
					mnesia:transaction(F),
					%%none;
				{"act","rm_usrgrp"} ->
					{"usr",RmUser} = lists:keyfind("usr", 1, Query),
					{"grp",RmGroup} = lists:keyfind("grp", 1, Query),
					F = fun() ->
						mnesia:delete_object(#restrictions_users{usr=RmUser, grp=RmGroup})
					end,
					mnesia:transaction(F),
				{"act","add_grpdest"} -> %% add user to group
					{"grp",NewGroup} = lists:keyfind("grp", 1, Query),
					{"dest",NewDestination} = lists:keyfind("dest", 1, Query),
					F = fun() ->
						mnesia:write(#restrictions_groups{grp=NewGroup, dest=NewDestination})
					end,
					mnesia:transaction(F),
					%%none;
				{"act","rm_grpdest"} ->
					{"grp",RmGroup} = lists:keyfind("grp", 1, Query),
					{"dest",RmDestination} = lists:keyfind("dest", 1, Query),
					F = fun() ->
						mnesia:delete_object(#restrictions_groups{grp=RmGroup, dest=RmDestination})
					end,
					mnesia:transaction(F),
				_ -> none
			end;
		_ -> none
	end,
    Res = [?XC("h1", "Restriction module manager"),
			?XE("table",[
				?XE("tr",
					[?XC("th","Users"),?XC("th","Groups")]
				),
				?XE("tr",
					[?XAE("td",[{"style","vertical-align:top;"}],web_user_list()),?XAE("td",[{"style","vertical-align:top;"}],web_group_list())] %% users and groups list with action buttons
				)]
			)				
		  ],
    {stop, Res};

web_page_host(Acc, _) -> Acc.

web_user_list() ->
	[?XE("table",
		[?XE("tr",
			[?XC("th","User"),?XC("th","Group")]
		)] ++
		lists:map(fun web_user_list/1,mnesia:dirty_match_object(mnesia:table_info(restrictions_users,wild_pattern)))),
			?XAE("form",[{"action", ""},{"method", "post"}],[
				?INPUT("text","usr",""),							
				?INPUT("text","grp",""),
				?INPUT("hidden","act","add_usrgrp"),
				?INPUT("submit","btn","Add")
			])
		].
	
web_user_list({restrictions_users,User,Group}) ->
	?XE("tr",
			[?XC("td",User),?XC("td",Group),
				?XE("td",
					[?XAE("form",[{"action", ""},{"method", "post"}],[
						?INPUT("hidden","act","rm_usrgrp"),
						?INPUT("hidden","usr",User),
						?INPUT("hidden","grp",Group),
						?INPUT("submit","btn","X")
					])]	
				)]
	).

web_group_list() ->
	[?XE("table",
		[?XE("tr",
			[?XC("th","Group can send to"),?XC("th","Destination")]
		)] ++
		lists:map(fun web_group_list/1,mnesia:dirty_match_object(mnesia:table_info(restrictions_groups,wild_pattern)))),
			?XAE("form",[{"action", ""},{"method", "post"}],[
				?INPUT("text","grp",""),
				?INPUT("text","dest",""),
				?INPUT("hidden","act","add_grpdest"),
				?INPUT("submit","btn","Add")
			])
		].
	
web_group_list({restrictions_groups,Group,Destination}) ->
	?XE("tr",
			[?XC("td",Group),?XC("td",Destination),
				?XE("td",
					[?XAE("form",[{"action", ""},{"method", "post"}],[
						?INPUT("hidden","act","rm_grpdest"),
						?INPUT("hidden","grp",Group),
						?INPUT("hidden","dest",Destination),
						?INPUT("submit","btn","X")
					])]	
				)]
	).
