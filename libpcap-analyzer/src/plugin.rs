use crate::packet_data::PacketData;

pub trait PluginBuilder : Sync + Send {
    fn name(&self) -> &'static str;
    fn build(&self) -> Box<Plugin>;
}

pub trait Plugin : Sync + Send {
    fn name(&self) -> &'static str;

    fn handle_l2(&mut self, _data: &[u8]) { }
    fn handle_l3(&mut self, _data: &[u8], _ethertype:u16) { }

    fn handle_l4(&mut self, _packet: &PacketData) { }

    fn pre_process(&mut self) {}
    fn post_process(&mut self) {}
}

#[macro_export]
macro_rules! default_plugin_builder {
    ($name:ident,$builder:ident) => {
        pub struct $builder;

        impl PluginBuilder for $builder {
            fn name(&self) -> &'static str { "$builder" }
            fn build(&self) -> Box<Plugin> {
                Box::new($name::default())
            }
        }
    }
}
