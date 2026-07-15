include $(TOPDIR)/rules.mk

PKG_NAME:=naiveproxy
PKG_VERSION:=$(NAIVE_VERSION)
PKG_RELEASE:=$(NAIVE_RELEASE)
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_LICENSE:=BSD-3-Clause
PKG_MAINTAINER:=NaiveProxy contributors
PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/naiveproxy
  SECTION:=net
  CATEGORY:=Network
  TITLE:=NaiveProxy client
  URL:=https://github.com/klzgrad/naiveproxy
endef

define Package/naiveproxy/description
  NaiveProxy client built from the corresponding NaiveProxy release.
endef

define Build/Prepare
	$(RM) -r $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(NAIVE_BINARY) $(PKG_BUILD_DIR)/naive
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/naiveproxy/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/naive $(1)/usr/bin/naive
endef

$(eval $(call BuildPackage,naiveproxy))
