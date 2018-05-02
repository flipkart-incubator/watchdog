$(document).ready(function(){
    var sortable = true;
    
    var data = get_data();

    $('#table').bootstrapTable({
        url: "api/get_all_challenges_data.php",
        columns: [{
            field: 'id',
            title: 'Id',
            valign: 'middle',
            align: "center"
        },{
            field: 'name',
            title: 'Name',
            valign: 'middle',
            sortable: sortable,
            events: show_chall,
            width: "60%",
            formatter: function (data, row, type){
                return "<a href='/challenges/challenge.php?id="+row.id+"' target='_blank'>"+data+"</a>";
            }
        }, {
            field: 'language',
            title: 'Language',
            align: 'center',
            valign: 'middle',
            sortable: sortable
        }, {
            field: 'type',
            title: 'Type',
            align: 'center',
            valign: 'middle',
            sortable: sortable
        }, {
            field: 'difficulty',
            title: 'Difficulty',
            align: 'center',
            valign: 'middle',
            sortable: sortable,
            formatter: function (data, type, row){
                if(data == "easy")
                    var diff = 'btn-success';
                if(data == "medium")
                    var diff = 'btn-warning';
                if(data == "hard")
                    var diff = 'btn-danger';

                return '<span class="'+data+'">'+data+'</span>';
            }
        }, {
            field: 'approved',
            title: 'Approve?',
            align: 'center',
            valign: 'middle',
            events: approve_challenge,
            formatter: operateFormatter,
            sortable: sortable
        }, {
            field: 'enabled',
            title: 'Enable?',
            align: 'center',
            valign: 'middle',
            events: enable_challenge,
            formatter: operateFormatter,
            sortable: sortable
        }, {
            field: 'id',
            title: 'Edit',
            align: 'center',
            valign: 'middle',
            formatter: function ( data, type, row ) 
                {
                    var ele = '<a href="?id='+data+'"><button type="button" class="btn btn-info">Edit</button></a>';
                    return ele;
                }
        }
        ]
    });
});

window.show_chall = {
    'click #myBtn': function (e, value, row, index) {
        console.log(row);
        $("#chall_name").text(row.name);
        $("#chall_type").text(row.type);
        $("#chall_lang").text(row.language);
        $("#chall_diff").text(row.difficulty);
        $("#chall_intro").text(row.introduction);
        $("#chall_instr").text(row.instructions);
        $("#chall_ref").text(row.reference);
    }
};

function get_data(){
    $.getJSON("api/get_all_challenges_data.php",function(data1,success){
        return data1;
    });
}

function operateFormatter(value, row, index) {
    
    var checked = "";
    if(value == "1"){
        checked = "checked";
    }
    else{
        checked = "";
    }
    return [
        '<a class="like" href="javascript:void(0)" >',
            '<label class="switch">',
              '<input style="width:24px" type="checkbox"'+checked+'>',
              '<span class="slider"></span>',
            '</label>',
        '</a>'
    ].join('');
}

window.approve_challenge = {
    'click .like': function (e, value, row, index) {
        var url = "api/update_challenge_state.php";
        action = "rejected";
        if(row.approved != 1)
            action = "approved";
        var data = {
            id: row.id,
            action: action
        };

        $.post(url, data, function(data1,success){
            print_message(row, action);
            $.getJSON("api/get_all_challenges_data.php",function(data1,success){
                $("#table").bootstrapTable("load",data1);
            });            
        });
    }
};

window.enable_challenge = {
    'click .like': function (e, value, row, index) {
        console.log(row);
        var url = "api/update_challenge_state.php";
        action = "disabled";
        if(row.enabled != 1)
            action = "enabled";

        var data = {
            id: row.id,
            action: action
        };

        $.post(url, data, function(data1,success){
            print_message(row, action);
            $.getJSON("api/get_all_challenges_data.php",function(data1,success){
                $("#table").bootstrapTable("load",data1);
            });
        });
    }
};

function update_challenge_state(id,action){
    var url = "view_edit.php";
    data = 'id='+id+'&action='+action;

    $.post(url, data, function(data1,success){
        alert('Challenge with ID: \''+id+'\' is \''+action+'\'');
        window.location = ""
    });
}

function print_message(row, action){
    var info = 'challenge with id: '+row.id+' is '+action;
    if(action == "approved")
    {
        $("#result").removeClass("alert alert-danger");
        $("#result").addClass("alert alert-success");
    }
    else
    {
        $("#result").removeClass("alert alert-success");
        $("#result").addClass("alert alert-danger");
    }
    
    $("#result").html(info); 
}









